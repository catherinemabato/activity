// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// tailscale-operator provides a way to expose services running in a Kubernetes
// cluster to your Tailnet.
package main

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/oauth2/clientcredentials"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	kzap "sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/yaml"
	"tailscale.com/client/tailscale"
	"tailscale.com/hostinfo"
	"tailscale.com/ipn"
	"tailscale.com/ipn/store/kubestore"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
	"tailscale.com/types/opt"
	"tailscale.com/util/dnsname"
	"tailscale.com/version"
)

func main() {
	// Required to use our client API. We're fine with the instability since the
	// client lives in the same repo as this code.
	tailscale.I_Acknowledge_This_API_Is_Unstable = true

	var (
		tsNamespace        = defaultEnv("OPERATOR_NAMESPACE", "")
		tslogging          = defaultEnv("OPERATOR_LOGGING", "info")
		image              = defaultEnv("PROXY_IMAGE", "tailscale/tailscale:latest")
		priorityClassName  = defaultEnv("PROXY_PRIORITY_CLASS_NAME", "")
		tags               = defaultEnv("PROXY_TAGS", "tag:k8s")
		shouldRunAuthProxy = defaultBool("AUTH_PROXY", false)
	)

	var opts []kzap.Opts
	switch tslogging {
	case "info":
		opts = append(opts, kzap.Level(zapcore.InfoLevel))
	case "debug":
		opts = append(opts, kzap.Level(zapcore.DebugLevel))
	case "dev":
		opts = append(opts, kzap.UseDevMode(true), kzap.Level(zapcore.DebugLevel))
	}
	zlog := kzap.NewRaw(opts...).Sugar()
	logf.SetLogger(zapr.NewLogger(zlog.Desugar()))

	s, tsClient := initTSNet(zlog)
	restConfig := config.GetConfigOrDie()
	if shouldRunAuthProxy {
		launchAuthProxy(zlog, restConfig, s)
	}
	startReconcilers(zlog, tsNamespace, restConfig, tsClient, image, priorityClassName, tags)
}

// initTSNet initializes the tsnet.Server and logs in to Tailscale. It uses the
// CLIENT_ID_FILE and CLIENT_SECRET_FILE environment variables to authenticate
// with Tailscale.
func initTSNet(zlog *zap.SugaredLogger) (*tsnet.Server, *tailscale.Client) {
	hostinfo.SetApp("k8s-operator")
	var (
		clientIDPath     = defaultEnv("CLIENT_ID_FILE", "")
		clientSecretPath = defaultEnv("CLIENT_SECRET_FILE", "")
		hostname         = defaultEnv("OPERATOR_HOSTNAME", "tailscale-operator")
		kubeSecret       = defaultEnv("OPERATOR_SECRET", "")
		operatorTags     = defaultEnv("OPERATOR_INITIAL_TAGS", "tag:k8s-operator")
	)
	startlog := zlog.Named("startup")
	if clientIDPath == "" || clientSecretPath == "" {
		startlog.Fatalf("CLIENT_ID_FILE and CLIENT_SECRET_FILE must be set")
	}
	clientID, err := os.ReadFile(clientIDPath)
	if err != nil {
		startlog.Fatalf("reading client ID %q: %v", clientIDPath, err)
	}
	clientSecret, err := os.ReadFile(clientSecretPath)
	if err != nil {
		startlog.Fatalf("reading client secret %q: %v", clientSecretPath, err)
	}
	credentials := clientcredentials.Config{
		ClientID:     string(clientID),
		ClientSecret: string(clientSecret),
		TokenURL:     "https://login.tailscale.com/api/v2/oauth/token",
	}
	tsClient := tailscale.NewClient("-", nil)
	tsClient.HTTPClient = credentials.Client(context.Background())

	s := &tsnet.Server{
		Hostname: hostname,
		Logf:     zlog.Named("tailscaled").Debugf,
	}
	if kubeSecret != "" {
		st, err := kubestore.New(logger.Discard, kubeSecret)
		if err != nil {
			startlog.Fatalf("creating kube store: %v", err)
		}
		s.Store = st
	}
	if err := s.Start(); err != nil {
		startlog.Fatalf("starting tailscale server: %v", err)
	}
	defer s.Close()
	lc, err := s.LocalClient()
	if err != nil {
		startlog.Fatalf("getting local client: %v", err)
	}

	ctx := context.Background()
	loginDone := false
	machineAuthShown := false
waitOnline:
	for {
		startlog.Debugf("querying tailscaled status")
		st, err := lc.StatusWithoutPeers(ctx)
		if err != nil {
			startlog.Fatalf("getting status: %v", err)
		}
		switch st.BackendState {
		case "Running":
			break waitOnline
		case "NeedsLogin":
			if loginDone {
				break
			}
			caps := tailscale.KeyCapabilities{
				Devices: tailscale.KeyDeviceCapabilities{
					Create: tailscale.KeyDeviceCreateCapabilities{
						Reusable:      false,
						Preauthorized: true,
						Tags:          strings.Split(operatorTags, ","),
					},
				},
			}
			authkey, _, err := tsClient.CreateKey(ctx, caps)
			if err != nil {
				startlog.Fatalf("creating operator authkey: %v", err)
			}
			if err := lc.Start(ctx, ipn.Options{
				AuthKey: authkey,
			}); err != nil {
				startlog.Fatalf("starting tailscale: %v", err)
			}
			if err := lc.StartLoginInteractive(ctx); err != nil {
				startlog.Fatalf("starting login: %v", err)
			}
			startlog.Debugf("requested login by authkey")
			loginDone = true
		case "NeedsMachineAuth":
			if !machineAuthShown {
				startlog.Infof("Machine approval required, please visit the admin panel to approve")
				machineAuthShown = true
			}
		default:
			startlog.Debugf("waiting for tailscale to start: %v", st.BackendState)
		}
		time.Sleep(time.Second)
	}
	return s, tsClient
}

// startReconcilers starts the controller-runtime manager and registers the
// ServiceReconciler.
func startReconcilers(zlog *zap.SugaredLogger, tsNamespace string, restConfig *rest.Config, tsClient *tailscale.Client, image, priorityClassName, tags string) {
	startlog := zlog.Named("startReconcilers")
	// For secrets and statefulsets, we only get permission to touch the objects
	// in the controller's own namespace. This cannot be expressed by
	// .Watches(...) below, instead you have to add a per-type field selector to
	// the cache that sits a few layers below the builder stuff, which will
	// implicitly filter what parts of the world the builder code gets to see at
	// all.
	nsFilter := cache.ByObject{
		Field: client.InNamespace(tsNamespace).AsSelector(),
	}
	mgr, err := manager.New(restConfig, manager.Options{
		Cache: cache.Options{
			ByObject: map[client.Object]cache.ByObject{
				&corev1.Secret{}:      nsFilter,
				&appsv1.StatefulSet{}: nsFilter,
			},
		},
	})
	if err != nil {
		startlog.Fatalf("could not create manager: %v", err)
	}

	reconcileFilter := handler.EnqueueRequestsFromMapFunc(func(_ context.Context, o client.Object) []reconcile.Request {
		ls := o.GetLabels()
		if ls[LabelManaged] != "true" {
			return nil
		}
		if ls[LabelParentType] != "svc" {
			return nil
		}
		return []reconcile.Request{
			{
				NamespacedName: types.NamespacedName{
					Namespace: ls[LabelParentNamespace],
					Name:      ls[LabelParentName],
				},
			},
		}
	})
	err = builder.
		ControllerManagedBy(mgr).
		For(&corev1.Service{}).
		Watches(&appsv1.StatefulSet{}, reconcileFilter).
		Watches(&corev1.Secret{}, reconcileFilter).
		Complete(&ServiceReconciler{
			ssr: &tailscaleSTSReconciler{
				Client:                 mgr.GetClient(),
				tsClient:               tsClient,
				defaultTags:            strings.Split(tags, ","),
				operatorNamespace:      tsNamespace,
				proxyImage:             image,
				proxyPriorityClassName: priorityClassName,
			},
			Client: mgr.GetClient(),
			logger: zlog.Named("service-reconciler"),
		})
	if err != nil {
		startlog.Fatalf("could not create controller: %v", err)
	}

	startlog.Infof("Startup complete, operator running, version: %s", version.Long())
	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		startlog.Fatalf("could not start manager: %v", err)
	}
}

const (
	LabelManaged         = "tailscale.com/managed"
	LabelParentType      = "tailscale.com/parent-resource-type"
	LabelParentName      = "tailscale.com/parent-resource"
	LabelParentNamespace = "tailscale.com/parent-resource-ns"

	FinalizerName = "tailscale.com/finalizer"

	AnnotationExpose   = "tailscale.com/expose"
	AnnotationTags     = "tailscale.com/tags"
	AnnotationHostname = "tailscale.com/hostname"
)

type ServiceReconciler struct {
	client.Client
	ssr    *tailscaleSTSReconciler
	logger *zap.SugaredLogger
}

type tsClient interface {
	CreateKey(ctx context.Context, caps tailscale.KeyCapabilities) (string, *tailscale.Key, error)
	DeleteDevice(ctx context.Context, nodeStableID string) error
}

func childResourceLabels(parent *corev1.Service) map[string]string {
	// You might wonder why we're using owner references, since they seem to be
	// built for exactly this. Unfortunately, Kubernetes does not support
	// cross-namespace ownership, by design. This means we cannot make the
	// service being exposed the owner of the implementation details of the
	// proxying. Instead, we have to do our own filtering and tracking with
	// labels.
	return map[string]string{
		LabelManaged:         "true",
		LabelParentName:      parent.GetName(),
		LabelParentNamespace: parent.GetNamespace(),
		LabelParentType:      "svc",
	}
}

func (a *ServiceReconciler) Reconcile(ctx context.Context, req reconcile.Request) (_ reconcile.Result, err error) {
	logger := a.logger.With("service-ns", req.Namespace, "service-name", req.Name)
	logger.Debugf("starting reconcile")
	defer logger.Debugf("reconcile finished")

	svc := new(corev1.Service)
	err = a.Get(ctx, req.NamespacedName, svc)
	if apierrors.IsNotFound(err) {
		// Request object not found, could have been deleted after reconcile request.
		logger.Debugf("service not found, assuming it was deleted")
		return reconcile.Result{}, nil
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get svc: %w", err)
	}
	if !svc.DeletionTimestamp.IsZero() || !a.shouldExpose(svc) {
		logger.Debugf("service is being deleted or should not be exposed, cleaning up")
		return reconcile.Result{}, a.maybeCleanup(ctx, logger, svc)
	}

	return reconcile.Result{}, a.maybeProvision(ctx, logger, svc)
}

// maybeCleanup removes any existing resources related to serving svc over tailscale.
//
// This function is responsible for removing the finalizer from the service,
// once all associated resources are gone.
func (a *ServiceReconciler) maybeCleanup(ctx context.Context, logger *zap.SugaredLogger, svc *corev1.Service) error {
	ix := slices.Index(svc.Finalizers, FinalizerName)
	if ix < 0 {
		logger.Debugf("no finalizer, nothing to do")
		return nil
	}

	if done, err := a.ssr.Cleanup(ctx, logger, childResourceLabels(svc)); err != nil {
		return fmt.Errorf("failed to cleanup: %w", err)
	} else if !done {
		logger.Debugf("cleanup not done yet, waiting for next reconcile")
		return nil
	}

	svc.Finalizers = append(svc.Finalizers[:ix], svc.Finalizers[ix+1:]...)
	if err := a.Update(ctx, svc); err != nil {
		return fmt.Errorf("failed to remove finalizer: %w", err)
	}

	// Unlike most log entries in the reconcile loop, this will get printed
	// exactly once at the very end of cleanup, because the final step of
	// cleanup removes the tailscale finalizer, which will make all future
	// reconciles exit early.
	logger.Infof("unexposed service from tailnet")
	return nil
}

// maybeProvision ensures that svc is exposed over tailscale, taking any actions
// necessary to reach that state.
//
// This function adds a finalizer to svc, ensuring that we can handle orderly
// deprovisioning later.
func (a *ServiceReconciler) maybeProvision(ctx context.Context, logger *zap.SugaredLogger, svc *corev1.Service) error {
	hostname, err := nameForService(svc)
	if err != nil {
		return err
	}

	if !slices.Contains(svc.Finalizers, FinalizerName) {
		// This log line is printed exactly once during initial provisioning,
		// because once the finalizer is in place this block gets skipped. So,
		// this is a nice place to tell the operator that the high level,
		// multi-reconcile operation is underway.
		logger.Infof("exposing service over tailscale")
		svc.Finalizers = append(svc.Finalizers, FinalizerName)
		if err := a.Update(ctx, svc); err != nil {
			return fmt.Errorf("failed to add finalizer: %w", err)
		}
	}
	crl := childResourceLabels(svc)
	var tags []string
	if tstr, ok := svc.Annotations[AnnotationTags]; ok {
		tags = strings.Split(tstr, ",")
	}

	sts := &tailscaleSTSConfig{
		ParentResourceName:  svc.Name,
		ParentResourceUID:   string(svc.UID),
		TargetIP:            svc.Spec.ClusterIP,
		Hostname:            hostname,
		Tags:                tags,
		ChildResourceLabels: crl,
	}

	if err := a.ssr.Provision(ctx, logger, sts); err != nil {
		return fmt.Errorf("failed to provision: %w", err)
	}

	if !a.hasLoadBalancerClass(svc) {
		logger.Debugf("service is not a LoadBalancer, so not updating ingress")
		return nil
	}

	_, tsHost, err := a.ssr.DeviceInfo(ctx, crl)
	if err != nil {
		return fmt.Errorf("failed to get device ID: %w", err)
	}
	if tsHost == "" {
		logger.Debugf("no Tailscale hostname known yet, waiting for proxy pod to finish auth")
		// No hostname yet. Wait for the proxy pod to auth.
		svc.Status.LoadBalancer.Ingress = nil
		if err := a.Status().Update(ctx, svc); err != nil {
			return fmt.Errorf("failed to update service status: %w", err)
		}
		return nil
	}

	logger.Debugf("setting ingress hostname to %q", tsHost)
	svc.Status.LoadBalancer.Ingress = []corev1.LoadBalancerIngress{
		{
			Hostname: tsHost,
		},
	}
	if err := a.Status().Update(ctx, svc); err != nil {
		return fmt.Errorf("failed to update service status: %w", err)
	}
	return nil
}

func (a *ServiceReconciler) shouldExpose(svc *corev1.Service) bool {
	// Headless services can't be exposed, since there is no ClusterIP to
	// forward to.
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		return false
	}

	return a.hasLoadBalancerClass(svc) || a.hasAnnotation(svc)
}

func (a *ServiceReconciler) hasLoadBalancerClass(svc *corev1.Service) bool {
	return svc != nil &&
		svc.Spec.Type == corev1.ServiceTypeLoadBalancer &&
		svc.Spec.LoadBalancerClass != nil &&
		*svc.Spec.LoadBalancerClass == "tailscale"
}

func (a *ServiceReconciler) hasAnnotation(svc *corev1.Service) bool {
	return svc != nil &&
		svc.Annotations[AnnotationExpose] == "true"
}

type tailscaleSTSConfig struct {
	ParentResourceName  string
	ParentResourceUID   string
	ChildResourceLabels map[string]string

	TargetIP string

	Hostname string
	Tags     []string // if empty, use defaultTags
}

type tailscaleSTSReconciler struct {
	client.Client
	tsClient               tsClient
	defaultTags            []string
	operatorNamespace      string
	proxyImage             string
	proxyPriorityClassName string
}

// Provision ensures that the StatefulSet for the given service is running and
// up to date.
func (a *tailscaleSTSReconciler) Provision(ctx context.Context, logger *zap.SugaredLogger, sts *tailscaleSTSConfig) error {
	// Do full reconcile.
	hsvc, err := a.reconcileHeadlessService(ctx, logger, sts)
	if err != nil {
		return fmt.Errorf("failed to reconcile headless service: %w", err)
	}

	secretName, err := a.createOrGetSecret(ctx, logger, sts, hsvc)
	if err != nil {
		return fmt.Errorf("failed to create or get API key secret: %w", err)
	}
	_, err = a.reconcileSTS(ctx, logger, sts, hsvc, secretName)
	if err != nil {
		return fmt.Errorf("failed to reconcile statefulset: %w", err)
	}

	return nil
}

// Cleanup removes all resources associated that were created by Provision with
// the given labels. It returns true when all resources have been removed,
// otherwise it returns false and the caller should retry later.
func (a *tailscaleSTSReconciler) Cleanup(ctx context.Context, logger *zap.SugaredLogger, labels map[string]string) (done bool, _ error) {
	// Need to delete the StatefulSet first, and delete it with foreground
	// cascading deletion. That way, the pod that's writing to the Secret will
	// stop running before we start looking at the Secret's contents, and
	// assuming k8s ordering semantics don't mess with us, that should avoid
	// tailscale device deletion races where we fail to notice a device that
	// should be removed.
	sts, err := getSingleObject[appsv1.StatefulSet](ctx, a.Client, a.operatorNamespace, labels)
	if err != nil {
		return false, fmt.Errorf("getting statefulset: %w", err)
	}
	if sts != nil {
		if !sts.GetDeletionTimestamp().IsZero() {
			// Deletion in progress, check again later. We'll get another
			// notification when the deletion is complete.
			logger.Debugf("waiting for statefulset %s/%s deletion", sts.GetNamespace(), sts.GetName())
			return false, nil
		}
		err := a.DeleteAllOf(ctx, &appsv1.StatefulSet{}, client.InNamespace(a.operatorNamespace), client.MatchingLabels(labels), client.PropagationPolicy(metav1.DeletePropagationForeground))
		if err != nil {
			return false, fmt.Errorf("deleting statefulset: %w", err)
		}
		logger.Debugf("started deletion of statefulset %s/%s", sts.GetNamespace(), sts.GetName())
		return false, nil
	}

	id, _, err := a.DeviceInfo(ctx, labels)
	if err != nil {
		return false, fmt.Errorf("getting device info: %w", err)
	}
	if id != "" {
		// TODO: handle case where the device is already deleted, but the secret
		// is still around.
		if err := a.tsClient.DeleteDevice(ctx, string(id)); err != nil {
			return false, fmt.Errorf("deleting device: %w", err)
		}
	}

	types := []client.Object{
		&corev1.Service{},
		&corev1.Secret{},
	}
	for _, typ := range types {
		if err := a.DeleteAllOf(ctx, typ, client.InNamespace(a.operatorNamespace), client.MatchingLabels(labels)); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (a *tailscaleSTSReconciler) reconcileHeadlessService(ctx context.Context, logger *zap.SugaredLogger, sts *tailscaleSTSConfig) (*corev1.Service, error) {
	hsvc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "ts-" + sts.ParentResourceName + "-",
			Namespace:    a.operatorNamespace,
			Labels:       sts.ChildResourceLabels,
		},
		Spec: corev1.ServiceSpec{
			ClusterIP: "None",
			Selector: map[string]string{
				"app": sts.ParentResourceUID,
			},
		},
	}
	logger.Debugf("reconciling headless service for StatefulSet")
	return createOrUpdate(ctx, a.Client, a.operatorNamespace, hsvc, func(svc *corev1.Service) { svc.Spec = hsvc.Spec })
}

func (a *tailscaleSTSReconciler) createOrGetSecret(ctx context.Context, logger *zap.SugaredLogger, stsC *tailscaleSTSConfig, hsvc *corev1.Service) (string, error) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			// Hardcode a -0 suffix so that in future, if we support
			// multiple StatefulSet replicas, we can provision -N for
			// those.
			Name:      hsvc.Name + "-0",
			Namespace: a.operatorNamespace,
			Labels:    stsC.ChildResourceLabels,
		},
	}
	if err := a.Get(ctx, client.ObjectKeyFromObject(secret), secret); err == nil {
		logger.Debugf("secret %s/%s already exists", secret.GetNamespace(), secret.GetName())
		return secret.Name, nil
	} else if !apierrors.IsNotFound(err) {
		return "", err
	}

	// Secret doesn't exist yet, create one. Initially it contains
	// only the Tailscale authkey, but once Tailscale starts it'll
	// also store the daemon state.
	sts, err := getSingleObject[appsv1.StatefulSet](ctx, a.Client, a.operatorNamespace, stsC.ChildResourceLabels)
	if err != nil {
		return "", err
	}
	if sts != nil {
		// StatefulSet exists, so we have already created the secret.
		// If the secret is missing, they should delete the StatefulSet.
		logger.Errorf("Tailscale proxy secret doesn't exist, but the corresponding StatefulSet %s/%s already does. Something is wrong, please delete the StatefulSet.", sts.GetNamespace(), sts.GetName())
		return "", nil
	}
	// Create API Key secret which is going to be used by the statefulset
	// to authenticate with Tailscale.
	logger.Debugf("creating authkey for new tailscale proxy")
	tags := stsC.Tags
	if len(tags) == 0 {
		tags = a.defaultTags
	}
	authKey, err := a.newAuthKey(ctx, tags)
	if err != nil {
		return "", err
	}

	secret.StringData = map[string]string{
		"authkey": authKey,
	}
	if err := a.Create(ctx, secret); err != nil {
		return "", err
	}
	return secret.Name, nil
}

// DeviceInfo returns the device ID and hostname for the Tailscale device
// associated with the given labels.
func (a *tailscaleSTSReconciler) DeviceInfo(ctx context.Context, childLabels map[string]string) (id tailcfg.StableNodeID, hostname string, err error) {
	sec, err := getSingleObject[corev1.Secret](ctx, a.Client, a.operatorNamespace, childLabels)
	if err != nil {
		return "", "", err
	}
	if sec == nil {
		return "", "", nil
	}
	id = tailcfg.StableNodeID(sec.Data["device_id"])
	if id == "" {
		return "", "", nil
	}
	// Kubernetes chokes on well-formed FQDNs with the trailing dot, so we have
	// to remove it.
	hostname = strings.TrimSuffix(string(sec.Data["device_fqdn"]), ".")
	if hostname == "" {
		return "", "", nil
	}
	return id, hostname, nil
}

func (a *tailscaleSTSReconciler) newAuthKey(ctx context.Context, tags []string) (string, error) {
	caps := tailscale.KeyCapabilities{
		Devices: tailscale.KeyDeviceCapabilities{
			Create: tailscale.KeyDeviceCreateCapabilities{
				Reusable:      false,
				Preauthorized: true,
				Tags:          tags,
			},
		},
	}

	key, _, err := a.tsClient.CreateKey(ctx, caps)
	if err != nil {
		return "", err
	}
	return key, nil
}

//go:embed manifests/proxy.yaml
var proxyYaml []byte

func (a *tailscaleSTSReconciler) reconcileSTS(ctx context.Context, logger *zap.SugaredLogger, sts *tailscaleSTSConfig, headlessSvc *corev1.Service, authKeySecret string) (*appsv1.StatefulSet, error) {
	var ss appsv1.StatefulSet
	if err := yaml.Unmarshal(proxyYaml, &ss); err != nil {
		return nil, fmt.Errorf("failed to unmarshal proxy spec: %w", err)
	}
	container := &ss.Spec.Template.Spec.Containers[0]
	container.Image = a.proxyImage
	container.Env = append(container.Env,
		corev1.EnvVar{
			Name:  "TS_DEST_IP",
			Value: sts.TargetIP,
		},
		corev1.EnvVar{
			Name:  "TS_KUBE_SECRET",
			Value: authKeySecret,
		},
		corev1.EnvVar{
			Name:  "TS_HOSTNAME",
			Value: sts.Hostname,
		})
	ss.ObjectMeta = metav1.ObjectMeta{
		Name:      headlessSvc.Name,
		Namespace: a.operatorNamespace,
		Labels:    sts.ChildResourceLabels,
	}
	ss.Spec.ServiceName = headlessSvc.Name
	ss.Spec.Selector = &metav1.LabelSelector{
		MatchLabels: map[string]string{
			"app": sts.ParentResourceUID,
		},
	}
	ss.Spec.Template.ObjectMeta.Labels = map[string]string{
		"app": sts.ParentResourceUID,
	}
	ss.Spec.Template.Spec.PriorityClassName = a.proxyPriorityClassName
	logger.Debugf("reconciling statefulset %s/%s", ss.GetNamespace(), ss.GetName())
	return createOrUpdate(ctx, a.Client, a.operatorNamespace, &ss, func(s *appsv1.StatefulSet) { s.Spec = ss.Spec })
}

// ptrObject is a type constraint for pointer types that implement
// client.Object.
type ptrObject[T any] interface {
	client.Object
	*T
}

// createOrUpdate adds obj to the k8s cluster, unless the object already exists,
// in which case update is called to make changes to it. If update is nil, the
// existing object is returned unmodified.
//
// obj is looked up by its Name and Namespace if Name is set, otherwise it's
// looked up by labels.
func createOrUpdate[T any, O ptrObject[T]](ctx context.Context, c client.Client, ns string, obj O, update func(O)) (O, error) {
	var (
		existing O
		err      error
	)
	if obj.GetName() != "" {
		existing = new(T)
		existing.SetName(obj.GetName())
		existing.SetNamespace(obj.GetNamespace())
		err = c.Get(ctx, client.ObjectKeyFromObject(obj), existing)
	} else {
		existing, err = getSingleObject[T, O](ctx, c, ns, obj.GetLabels())
	}
	if err == nil && existing != nil {
		if update != nil {
			update(existing)
			if err := c.Update(ctx, existing); err != nil {
				return nil, err
			}
		}
		return existing, nil
	}
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, fmt.Errorf("failed to get object: %w", err)
	}
	if err := c.Create(ctx, obj); err != nil {
		return nil, err
	}
	return obj, nil
}

// getSingleObject searches for k8s objects of type T
// (e.g. corev1.Service) with the given labels, and returns
// it. Returns nil if no objects match the labels, and an error if
// more than one object matches.
func getSingleObject[T any, O ptrObject[T]](ctx context.Context, c client.Client, ns string, labels map[string]string) (O, error) {
	ret := O(new(T))
	kinds, _, err := c.Scheme().ObjectKinds(ret)
	if err != nil {
		return nil, err
	}
	if len(kinds) != 1 {
		// TODO: the runtime package apparently has a "pick the best
		// GVK" function somewhere that might be good enough?
		return nil, fmt.Errorf("more than 1 GroupVersionKind for %T", ret)
	}

	gvk := kinds[0]
	gvk.Kind += "List"
	lst := unstructured.UnstructuredList{}
	lst.SetGroupVersionKind(gvk)
	if err := c.List(ctx, &lst, client.InNamespace(ns), client.MatchingLabels(labels)); err != nil {
		return nil, err
	}

	if len(lst.Items) == 0 {
		return nil, nil
	}
	if len(lst.Items) > 1 {
		return nil, fmt.Errorf("found multiple matching %T objects", ret)
	}
	if err := c.Scheme().Convert(&lst.Items[0], ret, nil); err != nil {
		return nil, err
	}
	return ret, nil
}

func defaultBool(envName string, defVal bool) bool {
	vs := os.Getenv(envName)
	if vs == "" {
		return defVal
	}
	v, _ := opt.Bool(vs).Get()
	return v
}

func defaultEnv(envName, defVal string) string {
	v := os.Getenv(envName)
	if v == "" {
		return defVal
	}
	return v
}

func nameForService(svc *corev1.Service) (string, error) {
	if h, ok := svc.Annotations[AnnotationHostname]; ok {
		if err := dnsname.ValidLabel(h); err != nil {
			return "", fmt.Errorf("invalid Tailscale hostname %q: %w", h, err)
		}
		return h, nil
	}
	return svc.Namespace + "-" + svc.Name, nil
}
