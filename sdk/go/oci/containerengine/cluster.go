// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package containerengine

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Cluster resource in Oracle Cloud Infrastructure Container Engine service.
//
// Create a new cluster.
//
// ## Import
//
// Clusters can be imported using the `id`, e.g.
//
// ```sh
//
//	$ pulumi import oci:ContainerEngine/cluster:Cluster test_cluster "id"
//
// ```
type Cluster struct {
	pulumi.CustomResourceState

	// Available Kubernetes versions to which the clusters masters may be upgraded.
	AvailableKubernetesUpgrades pulumi.StringArrayOutput `pulumi:"availableKubernetesUpgrades"`
	// Available CNIs and network options for existing and new node pools of the cluster
	ClusterPodNetworkOptions ClusterClusterPodNetworkOptionArrayOutput `pulumi:"clusterPodNetworkOptions"`
	// The OCID of the compartment in which to create the cluster.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// The network configuration for access to the Cluster control plane.
	EndpointConfig ClusterEndpointConfigPtrOutput `pulumi:"endpointConfig"`
	// Endpoints served up by the cluster masters.
	Endpoints ClusterEndpointArrayOutput `pulumi:"endpoints"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
	ImagePolicyConfig ClusterImagePolicyConfigOutput `pulumi:"imagePolicyConfig"`
	// The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
	KmsKeyId pulumi.StringOutput `pulumi:"kmsKeyId"`
	// (Updatable) The version of Kubernetes to install into the cluster masters.
	KubernetesVersion pulumi.StringOutput `pulumi:"kubernetesVersion"`
	// Details about the state of the cluster masters.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// Metadata about the cluster.
	Metadatas ClusterMetadataArrayOutput `pulumi:"metadatas"`
	// (Updatable) The name of the cluster. Avoid entering confidential information.
	Name pulumi.StringOutput `pulumi:"name"`
	// (Updatable) Optional attributes for the cluster.
	Options ClusterOptionsOutput `pulumi:"options"`
	// The state of the cluster masters.
	State pulumi.StringOutput `pulumi:"state"`
	// The OCID of the virtual cloud network (VCN) in which to create the cluster.
	VcnId pulumi.StringOutput `pulumi:"vcnId"`
}

// NewCluster registers a new resource with the given unique name, arguments, and options.
func NewCluster(ctx *pulumi.Context,
	name string, args *ClusterArgs, opts ...pulumi.ResourceOption) (*Cluster, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.KubernetesVersion == nil {
		return nil, errors.New("invalid value for required argument 'KubernetesVersion'")
	}
	if args.VcnId == nil {
		return nil, errors.New("invalid value for required argument 'VcnId'")
	}
	var resource Cluster
	err := ctx.RegisterResource("oci:ContainerEngine/cluster:Cluster", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCluster gets an existing Cluster resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCluster(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *ClusterState, opts ...pulumi.ResourceOption) (*Cluster, error) {
	var resource Cluster
	err := ctx.ReadResource("oci:ContainerEngine/cluster:Cluster", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Cluster resources.
type clusterState struct {
	// Available Kubernetes versions to which the clusters masters may be upgraded.
	AvailableKubernetesUpgrades []string `pulumi:"availableKubernetesUpgrades"`
	// Available CNIs and network options for existing and new node pools of the cluster
	ClusterPodNetworkOptions []ClusterClusterPodNetworkOption `pulumi:"clusterPodNetworkOptions"`
	// The OCID of the compartment in which to create the cluster.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The network configuration for access to the Cluster control plane.
	EndpointConfig *ClusterEndpointConfig `pulumi:"endpointConfig"`
	// Endpoints served up by the cluster masters.
	Endpoints []ClusterEndpoint `pulumi:"endpoints"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
	ImagePolicyConfig *ClusterImagePolicyConfig `pulumi:"imagePolicyConfig"`
	// The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
	KmsKeyId *string `pulumi:"kmsKeyId"`
	// (Updatable) The version of Kubernetes to install into the cluster masters.
	KubernetesVersion *string `pulumi:"kubernetesVersion"`
	// Details about the state of the cluster masters.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// Metadata about the cluster.
	Metadatas []ClusterMetadata `pulumi:"metadatas"`
	// (Updatable) The name of the cluster. Avoid entering confidential information.
	Name *string `pulumi:"name"`
	// (Updatable) Optional attributes for the cluster.
	Options *ClusterOptions `pulumi:"options"`
	// The state of the cluster masters.
	State *string `pulumi:"state"`
	// The OCID of the virtual cloud network (VCN) in which to create the cluster.
	VcnId *string `pulumi:"vcnId"`
}

type ClusterState struct {
	// Available Kubernetes versions to which the clusters masters may be upgraded.
	AvailableKubernetesUpgrades pulumi.StringArrayInput
	// Available CNIs and network options for existing and new node pools of the cluster
	ClusterPodNetworkOptions ClusterClusterPodNetworkOptionArrayInput
	// The OCID of the compartment in which to create the cluster.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// The network configuration for access to the Cluster control plane.
	EndpointConfig ClusterEndpointConfigPtrInput
	// Endpoints served up by the cluster masters.
	Endpoints ClusterEndpointArrayInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
	ImagePolicyConfig ClusterImagePolicyConfigPtrInput
	// The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
	KmsKeyId pulumi.StringPtrInput
	// (Updatable) The version of Kubernetes to install into the cluster masters.
	KubernetesVersion pulumi.StringPtrInput
	// Details about the state of the cluster masters.
	LifecycleDetails pulumi.StringPtrInput
	// Metadata about the cluster.
	Metadatas ClusterMetadataArrayInput
	// (Updatable) The name of the cluster. Avoid entering confidential information.
	Name pulumi.StringPtrInput
	// (Updatable) Optional attributes for the cluster.
	Options ClusterOptionsPtrInput
	// The state of the cluster masters.
	State pulumi.StringPtrInput
	// The OCID of the virtual cloud network (VCN) in which to create the cluster.
	VcnId pulumi.StringPtrInput
}

func (ClusterState) ElementType() reflect.Type {
	return reflect.TypeOf((*clusterState)(nil)).Elem()
}

type clusterArgs struct {
	// Available CNIs and network options for existing and new node pools of the cluster
	ClusterPodNetworkOptions []ClusterClusterPodNetworkOption `pulumi:"clusterPodNetworkOptions"`
	// The OCID of the compartment in which to create the cluster.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// The network configuration for access to the Cluster control plane.
	EndpointConfig *ClusterEndpointConfig `pulumi:"endpointConfig"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
	ImagePolicyConfig *ClusterImagePolicyConfig `pulumi:"imagePolicyConfig"`
	// The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
	KmsKeyId *string `pulumi:"kmsKeyId"`
	// (Updatable) The version of Kubernetes to install into the cluster masters.
	KubernetesVersion string `pulumi:"kubernetesVersion"`
	// (Updatable) The name of the cluster. Avoid entering confidential information.
	Name *string `pulumi:"name"`
	// (Updatable) Optional attributes for the cluster.
	Options *ClusterOptions `pulumi:"options"`
	// The OCID of the virtual cloud network (VCN) in which to create the cluster.
	VcnId string `pulumi:"vcnId"`
}

// The set of arguments for constructing a Cluster resource.
type ClusterArgs struct {
	// Available CNIs and network options for existing and new node pools of the cluster
	ClusterPodNetworkOptions ClusterClusterPodNetworkOptionArrayInput
	// The OCID of the compartment in which to create the cluster.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// The network configuration for access to the Cluster control plane.
	EndpointConfig ClusterEndpointConfigPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
	ImagePolicyConfig ClusterImagePolicyConfigPtrInput
	// The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
	KmsKeyId pulumi.StringPtrInput
	// (Updatable) The version of Kubernetes to install into the cluster masters.
	KubernetesVersion pulumi.StringInput
	// (Updatable) The name of the cluster. Avoid entering confidential information.
	Name pulumi.StringPtrInput
	// (Updatable) Optional attributes for the cluster.
	Options ClusterOptionsPtrInput
	// The OCID of the virtual cloud network (VCN) in which to create the cluster.
	VcnId pulumi.StringInput
}

func (ClusterArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*clusterArgs)(nil)).Elem()
}

type ClusterInput interface {
	pulumi.Input

	ToClusterOutput() ClusterOutput
	ToClusterOutputWithContext(ctx context.Context) ClusterOutput
}

func (*Cluster) ElementType() reflect.Type {
	return reflect.TypeOf((**Cluster)(nil)).Elem()
}

func (i *Cluster) ToClusterOutput() ClusterOutput {
	return i.ToClusterOutputWithContext(context.Background())
}

func (i *Cluster) ToClusterOutputWithContext(ctx context.Context) ClusterOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ClusterOutput)
}

// ClusterArrayInput is an input type that accepts ClusterArray and ClusterArrayOutput values.
// You can construct a concrete instance of `ClusterArrayInput` via:
//
//	ClusterArray{ ClusterArgs{...} }
type ClusterArrayInput interface {
	pulumi.Input

	ToClusterArrayOutput() ClusterArrayOutput
	ToClusterArrayOutputWithContext(context.Context) ClusterArrayOutput
}

type ClusterArray []ClusterInput

func (ClusterArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Cluster)(nil)).Elem()
}

func (i ClusterArray) ToClusterArrayOutput() ClusterArrayOutput {
	return i.ToClusterArrayOutputWithContext(context.Background())
}

func (i ClusterArray) ToClusterArrayOutputWithContext(ctx context.Context) ClusterArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ClusterArrayOutput)
}

// ClusterMapInput is an input type that accepts ClusterMap and ClusterMapOutput values.
// You can construct a concrete instance of `ClusterMapInput` via:
//
//	ClusterMap{ "key": ClusterArgs{...} }
type ClusterMapInput interface {
	pulumi.Input

	ToClusterMapOutput() ClusterMapOutput
	ToClusterMapOutputWithContext(context.Context) ClusterMapOutput
}

type ClusterMap map[string]ClusterInput

func (ClusterMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Cluster)(nil)).Elem()
}

func (i ClusterMap) ToClusterMapOutput() ClusterMapOutput {
	return i.ToClusterMapOutputWithContext(context.Background())
}

func (i ClusterMap) ToClusterMapOutputWithContext(ctx context.Context) ClusterMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(ClusterMapOutput)
}

type ClusterOutput struct{ *pulumi.OutputState }

func (ClusterOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Cluster)(nil)).Elem()
}

func (o ClusterOutput) ToClusterOutput() ClusterOutput {
	return o
}

func (o ClusterOutput) ToClusterOutputWithContext(ctx context.Context) ClusterOutput {
	return o
}

// Available Kubernetes versions to which the clusters masters may be upgraded.
func (o ClusterOutput) AvailableKubernetesUpgrades() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *Cluster) pulumi.StringArrayOutput { return v.AvailableKubernetesUpgrades }).(pulumi.StringArrayOutput)
}

// Available CNIs and network options for existing and new node pools of the cluster
func (o ClusterOutput) ClusterPodNetworkOptions() ClusterClusterPodNetworkOptionArrayOutput {
	return o.ApplyT(func(v *Cluster) ClusterClusterPodNetworkOptionArrayOutput { return v.ClusterPodNetworkOptions }).(ClusterClusterPodNetworkOptionArrayOutput)
}

// The OCID of the compartment in which to create the cluster.
func (o ClusterOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Cluster) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o ClusterOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Cluster) pulumi.MapOutput { return v.DefinedTags }).(pulumi.MapOutput)
}

// The network configuration for access to the Cluster control plane.
func (o ClusterOutput) EndpointConfig() ClusterEndpointConfigPtrOutput {
	return o.ApplyT(func(v *Cluster) ClusterEndpointConfigPtrOutput { return v.EndpointConfig }).(ClusterEndpointConfigPtrOutput)
}

// Endpoints served up by the cluster masters.
func (o ClusterOutput) Endpoints() ClusterEndpointArrayOutput {
	return o.ApplyT(func(v *Cluster) ClusterEndpointArrayOutput { return v.Endpoints }).(ClusterEndpointArrayOutput)
}

// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o ClusterOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v *Cluster) pulumi.MapOutput { return v.FreeformTags }).(pulumi.MapOutput)
}

// (Updatable) The image verification policy for signature validation. Once a policy is created and enabled with one or more kms keys, the policy will ensure all images deployed has been signed with the key(s) attached to the policy.
func (o ClusterOutput) ImagePolicyConfig() ClusterImagePolicyConfigOutput {
	return o.ApplyT(func(v *Cluster) ClusterImagePolicyConfigOutput { return v.ImagePolicyConfig }).(ClusterImagePolicyConfigOutput)
}

// The OCID of the KMS key to be used as the master encryption key for Kubernetes secret encryption. When used, `kubernetesVersion` must be at least `v1.13.0`.
func (o ClusterOutput) KmsKeyId() pulumi.StringOutput {
	return o.ApplyT(func(v *Cluster) pulumi.StringOutput { return v.KmsKeyId }).(pulumi.StringOutput)
}

// (Updatable) The version of Kubernetes to install into the cluster masters.
func (o ClusterOutput) KubernetesVersion() pulumi.StringOutput {
	return o.ApplyT(func(v *Cluster) pulumi.StringOutput { return v.KubernetesVersion }).(pulumi.StringOutput)
}

// Details about the state of the cluster masters.
func (o ClusterOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *Cluster) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// Metadata about the cluster.
func (o ClusterOutput) Metadatas() ClusterMetadataArrayOutput {
	return o.ApplyT(func(v *Cluster) ClusterMetadataArrayOutput { return v.Metadatas }).(ClusterMetadataArrayOutput)
}

// (Updatable) The name of the cluster. Avoid entering confidential information.
func (o ClusterOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *Cluster) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// (Updatable) Optional attributes for the cluster.
func (o ClusterOutput) Options() ClusterOptionsOutput {
	return o.ApplyT(func(v *Cluster) ClusterOptionsOutput { return v.Options }).(ClusterOptionsOutput)
}

// The state of the cluster masters.
func (o ClusterOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *Cluster) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// The OCID of the virtual cloud network (VCN) in which to create the cluster.
func (o ClusterOutput) VcnId() pulumi.StringOutput {
	return o.ApplyT(func(v *Cluster) pulumi.StringOutput { return v.VcnId }).(pulumi.StringOutput)
}

type ClusterArrayOutput struct{ *pulumi.OutputState }

func (ClusterArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Cluster)(nil)).Elem()
}

func (o ClusterArrayOutput) ToClusterArrayOutput() ClusterArrayOutput {
	return o
}

func (o ClusterArrayOutput) ToClusterArrayOutputWithContext(ctx context.Context) ClusterArrayOutput {
	return o
}

func (o ClusterArrayOutput) Index(i pulumi.IntInput) ClusterOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Cluster {
		return vs[0].([]*Cluster)[vs[1].(int)]
	}).(ClusterOutput)
}

type ClusterMapOutput struct{ *pulumi.OutputState }

func (ClusterMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Cluster)(nil)).Elem()
}

func (o ClusterMapOutput) ToClusterMapOutput() ClusterMapOutput {
	return o
}

func (o ClusterMapOutput) ToClusterMapOutputWithContext(ctx context.Context) ClusterMapOutput {
	return o
}

func (o ClusterMapOutput) MapIndex(k pulumi.StringInput) ClusterOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Cluster {
		return vs[0].(map[string]*Cluster)[vs[1].(string)]
	}).(ClusterOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*ClusterInput)(nil)).Elem(), &Cluster{})
	pulumi.RegisterInputType(reflect.TypeOf((*ClusterArrayInput)(nil)).Elem(), ClusterArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*ClusterMapInput)(nil)).Elem(), ClusterMap{})
	pulumi.RegisterOutputType(ClusterOutput{})
	pulumi.RegisterOutputType(ClusterArrayOutput{})
	pulumi.RegisterOutputType(ClusterMapOutput{})
}