// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package devops

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Deploy Environment resource in Oracle Cloud Infrastructure Devops service.
//
// Creates a new deployment environment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/DevOps"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := DevOps.NewDeployEnvironment(ctx, "testDeployEnvironment", &DevOps.DeployEnvironmentArgs{
// 			DeployEnvironmentType: pulumi.Any(_var.Deploy_environment_deploy_environment_type),
// 			ProjectId:             pulumi.Any(oci_devops_project.Test_project.Id),
// 			ClusterId:             pulumi.Any(oci_containerengine_cluster.Test_cluster.Id),
// 			ComputeInstanceGroupSelectors: &devops.DeployEnvironmentComputeInstanceGroupSelectorsArgs{
// 				Items: devops.DeployEnvironmentComputeInstanceGroupSelectorsItemArray{
// 					&devops.DeployEnvironmentComputeInstanceGroupSelectorsItemArgs{
// 						SelectorType:       pulumi.Any(_var.Deploy_environment_compute_instance_group_selectors_items_selector_type),
// 						ComputeInstanceIds: pulumi.Any(_var.Deploy_environment_compute_instance_group_selectors_items_compute_instance_ids),
// 						Query:              pulumi.Any(_var.Deploy_environment_compute_instance_group_selectors_items_query),
// 						Region:             pulumi.Any(_var.Deploy_environment_compute_instance_group_selectors_items_region),
// 					},
// 				},
// 			},
// 			DefinedTags: pulumi.AnyMap{
// 				"foo-namespace.bar-key": pulumi.Any("value"),
// 			},
// 			Description: pulumi.Any(_var.Deploy_environment_description),
// 			DisplayName: pulumi.Any(_var.Deploy_environment_display_name),
// 			FreeformTags: pulumi.AnyMap{
// 				"bar-key": pulumi.Any("value"),
// 			},
// 			FunctionId: pulumi.Any(oci_functions_function.Test_function.Id),
// 			NetworkChannel: &devops.DeployEnvironmentNetworkChannelArgs{
// 				NetworkChannelType: pulumi.Any(_var.Deploy_environment_network_channel_network_channel_type),
// 				SubnetId:           pulumi.Any(oci_core_subnet.Test_subnet.Id),
// 				NsgIds:             pulumi.Any(_var.Deploy_environment_network_channel_nsg_ids),
// 			},
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
//
// ## Import
//
// DeployEnvironments can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:DevOps/deployEnvironment:DeployEnvironment test_deploy_environment "id"
// ```
type DeployEnvironment struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID of the Kubernetes cluster.
	ClusterId pulumi.StringOutput `pulumi:"clusterId"`
	// The OCID of a compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
	ComputeInstanceGroupSelectors DeployEnvironmentComputeInstanceGroupSelectorsOutput `pulumi:"computeInstanceGroupSelectors"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) Deployment environment type.
	DeployEnvironmentType pulumi.StringOutput `pulumi:"deployEnvironmentType"`
	// (Updatable) Optional description about the deployment environment.
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Deployment environment display name. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// (Updatable) The OCID of the Function.
	FunctionId pulumi.StringOutput `pulumi:"functionId"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// (Updatable) Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer's private network.
	NetworkChannel DeployEnvironmentNetworkChannelOutput `pulumi:"networkChannel"`
	// The OCID of a project.
	ProjectId pulumi.StringOutput `pulumi:"projectId"`
	// The current state of the deployment environment.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapOutput `pulumi:"systemTags"`
	// Time the deployment environment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// Time the deployment environment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewDeployEnvironment registers a new resource with the given unique name, arguments, and options.
func NewDeployEnvironment(ctx *pulumi.Context,
	name string, args *DeployEnvironmentArgs, opts ...pulumi.ResourceOption) (*DeployEnvironment, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.DeployEnvironmentType == nil {
		return nil, errors.New("invalid value for required argument 'DeployEnvironmentType'")
	}
	if args.ProjectId == nil {
		return nil, errors.New("invalid value for required argument 'ProjectId'")
	}
	var resource DeployEnvironment
	err := ctx.RegisterResource("oci:DevOps/deployEnvironment:DeployEnvironment", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDeployEnvironment gets an existing DeployEnvironment resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDeployEnvironment(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DeployEnvironmentState, opts ...pulumi.ResourceOption) (*DeployEnvironment, error) {
	var resource DeployEnvironment
	err := ctx.ReadResource("oci:DevOps/deployEnvironment:DeployEnvironment", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DeployEnvironment resources.
type deployEnvironmentState struct {
	// (Updatable) The OCID of the Kubernetes cluster.
	ClusterId *string `pulumi:"clusterId"`
	// The OCID of a compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
	ComputeInstanceGroupSelectors *DeployEnvironmentComputeInstanceGroupSelectors `pulumi:"computeInstanceGroupSelectors"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Deployment environment type.
	DeployEnvironmentType *string `pulumi:"deployEnvironmentType"`
	// (Updatable) Optional description about the deployment environment.
	Description *string `pulumi:"description"`
	// (Updatable) Deployment environment display name. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) The OCID of the Function.
	FunctionId *string `pulumi:"functionId"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// (Updatable) Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer's private network.
	NetworkChannel *DeployEnvironmentNetworkChannel `pulumi:"networkChannel"`
	// The OCID of a project.
	ProjectId *string `pulumi:"projectId"`
	// The current state of the deployment environment.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]interface{} `pulumi:"systemTags"`
	// Time the deployment environment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated *string `pulumi:"timeCreated"`
	// Time the deployment environment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type DeployEnvironmentState struct {
	// (Updatable) The OCID of the Kubernetes cluster.
	ClusterId pulumi.StringPtrInput
	// The OCID of a compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
	ComputeInstanceGroupSelectors DeployEnvironmentComputeInstanceGroupSelectorsPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Deployment environment type.
	DeployEnvironmentType pulumi.StringPtrInput
	// (Updatable) Optional description about the deployment environment.
	Description pulumi.StringPtrInput
	// (Updatable) Deployment environment display name. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// (Updatable) The OCID of the Function.
	FunctionId pulumi.StringPtrInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// (Updatable) Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer's private network.
	NetworkChannel DeployEnvironmentNetworkChannelPtrInput
	// The OCID of a project.
	ProjectId pulumi.StringPtrInput
	// The current state of the deployment environment.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.MapInput
	// Time the deployment environment was created. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeCreated pulumi.StringPtrInput
	// Time the deployment environment was updated. Format defined by [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339).
	TimeUpdated pulumi.StringPtrInput
}

func (DeployEnvironmentState) ElementType() reflect.Type {
	return reflect.TypeOf((*deployEnvironmentState)(nil)).Elem()
}

type deployEnvironmentArgs struct {
	// (Updatable) The OCID of the Kubernetes cluster.
	ClusterId *string `pulumi:"clusterId"`
	// (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
	ComputeInstanceGroupSelectors *DeployEnvironmentComputeInstanceGroupSelectors `pulumi:"computeInstanceGroupSelectors"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) Deployment environment type.
	DeployEnvironmentType string `pulumi:"deployEnvironmentType"`
	// (Updatable) Optional description about the deployment environment.
	Description *string `pulumi:"description"`
	// (Updatable) Deployment environment display name. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) The OCID of the Function.
	FunctionId *string `pulumi:"functionId"`
	// (Updatable) Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer's private network.
	NetworkChannel *DeployEnvironmentNetworkChannel `pulumi:"networkChannel"`
	// The OCID of a project.
	ProjectId string `pulumi:"projectId"`
}

// The set of arguments for constructing a DeployEnvironment resource.
type DeployEnvironmentArgs struct {
	// (Updatable) The OCID of the Kubernetes cluster.
	ClusterId pulumi.StringPtrInput
	// (Updatable) A collection of selectors. The combination of instances matching the selectors are included in the instance group.
	ComputeInstanceGroupSelectors DeployEnvironmentComputeInstanceGroupSelectorsPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.MapInput
	// (Updatable) Deployment environment type.
	DeployEnvironmentType pulumi.StringInput
	// (Updatable) Optional description about the deployment environment.
	Description pulumi.StringPtrInput
	// (Updatable) Deployment environment display name. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only.  See [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"bar-key": "value"}`
	FreeformTags pulumi.MapInput
	// (Updatable) The OCID of the Function.
	FunctionId pulumi.StringPtrInput
	// (Updatable) Specifies the configuration needed when the target Oracle Cloud Infrastructure resource, i.e., OKE cluster, resides in customer's private network.
	NetworkChannel DeployEnvironmentNetworkChannelPtrInput
	// The OCID of a project.
	ProjectId pulumi.StringInput
}

func (DeployEnvironmentArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*deployEnvironmentArgs)(nil)).Elem()
}

type DeployEnvironmentInput interface {
	pulumi.Input

	ToDeployEnvironmentOutput() DeployEnvironmentOutput
	ToDeployEnvironmentOutputWithContext(ctx context.Context) DeployEnvironmentOutput
}

func (*DeployEnvironment) ElementType() reflect.Type {
	return reflect.TypeOf((**DeployEnvironment)(nil)).Elem()
}

func (i *DeployEnvironment) ToDeployEnvironmentOutput() DeployEnvironmentOutput {
	return i.ToDeployEnvironmentOutputWithContext(context.Background())
}

func (i *DeployEnvironment) ToDeployEnvironmentOutputWithContext(ctx context.Context) DeployEnvironmentOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DeployEnvironmentOutput)
}

// DeployEnvironmentArrayInput is an input type that accepts DeployEnvironmentArray and DeployEnvironmentArrayOutput values.
// You can construct a concrete instance of `DeployEnvironmentArrayInput` via:
//
//          DeployEnvironmentArray{ DeployEnvironmentArgs{...} }
type DeployEnvironmentArrayInput interface {
	pulumi.Input

	ToDeployEnvironmentArrayOutput() DeployEnvironmentArrayOutput
	ToDeployEnvironmentArrayOutputWithContext(context.Context) DeployEnvironmentArrayOutput
}

type DeployEnvironmentArray []DeployEnvironmentInput

func (DeployEnvironmentArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DeployEnvironment)(nil)).Elem()
}

func (i DeployEnvironmentArray) ToDeployEnvironmentArrayOutput() DeployEnvironmentArrayOutput {
	return i.ToDeployEnvironmentArrayOutputWithContext(context.Background())
}

func (i DeployEnvironmentArray) ToDeployEnvironmentArrayOutputWithContext(ctx context.Context) DeployEnvironmentArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DeployEnvironmentArrayOutput)
}

// DeployEnvironmentMapInput is an input type that accepts DeployEnvironmentMap and DeployEnvironmentMapOutput values.
// You can construct a concrete instance of `DeployEnvironmentMapInput` via:
//
//          DeployEnvironmentMap{ "key": DeployEnvironmentArgs{...} }
type DeployEnvironmentMapInput interface {
	pulumi.Input

	ToDeployEnvironmentMapOutput() DeployEnvironmentMapOutput
	ToDeployEnvironmentMapOutputWithContext(context.Context) DeployEnvironmentMapOutput
}

type DeployEnvironmentMap map[string]DeployEnvironmentInput

func (DeployEnvironmentMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DeployEnvironment)(nil)).Elem()
}

func (i DeployEnvironmentMap) ToDeployEnvironmentMapOutput() DeployEnvironmentMapOutput {
	return i.ToDeployEnvironmentMapOutputWithContext(context.Background())
}

func (i DeployEnvironmentMap) ToDeployEnvironmentMapOutputWithContext(ctx context.Context) DeployEnvironmentMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DeployEnvironmentMapOutput)
}

type DeployEnvironmentOutput struct{ *pulumi.OutputState }

func (DeployEnvironmentOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DeployEnvironment)(nil)).Elem()
}

func (o DeployEnvironmentOutput) ToDeployEnvironmentOutput() DeployEnvironmentOutput {
	return o
}

func (o DeployEnvironmentOutput) ToDeployEnvironmentOutputWithContext(ctx context.Context) DeployEnvironmentOutput {
	return o
}

type DeployEnvironmentArrayOutput struct{ *pulumi.OutputState }

func (DeployEnvironmentArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DeployEnvironment)(nil)).Elem()
}

func (o DeployEnvironmentArrayOutput) ToDeployEnvironmentArrayOutput() DeployEnvironmentArrayOutput {
	return o
}

func (o DeployEnvironmentArrayOutput) ToDeployEnvironmentArrayOutputWithContext(ctx context.Context) DeployEnvironmentArrayOutput {
	return o
}

func (o DeployEnvironmentArrayOutput) Index(i pulumi.IntInput) DeployEnvironmentOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *DeployEnvironment {
		return vs[0].([]*DeployEnvironment)[vs[1].(int)]
	}).(DeployEnvironmentOutput)
}

type DeployEnvironmentMapOutput struct{ *pulumi.OutputState }

func (DeployEnvironmentMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DeployEnvironment)(nil)).Elem()
}

func (o DeployEnvironmentMapOutput) ToDeployEnvironmentMapOutput() DeployEnvironmentMapOutput {
	return o
}

func (o DeployEnvironmentMapOutput) ToDeployEnvironmentMapOutputWithContext(ctx context.Context) DeployEnvironmentMapOutput {
	return o
}

func (o DeployEnvironmentMapOutput) MapIndex(k pulumi.StringInput) DeployEnvironmentOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *DeployEnvironment {
		return vs[0].(map[string]*DeployEnvironment)[vs[1].(string)]
	}).(DeployEnvironmentOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*DeployEnvironmentInput)(nil)).Elem(), &DeployEnvironment{})
	pulumi.RegisterInputType(reflect.TypeOf((*DeployEnvironmentArrayInput)(nil)).Elem(), DeployEnvironmentArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DeployEnvironmentMapInput)(nil)).Elem(), DeployEnvironmentMap{})
	pulumi.RegisterOutputType(DeployEnvironmentOutput{})
	pulumi.RegisterOutputType(DeployEnvironmentArrayOutput{})
	pulumi.RegisterOutputType(DeployEnvironmentMapOutput{})
}
