// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package servicemesh

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Access Policy resource in Oracle Cloud Infrastructure Service Mesh service.
//
// Creates a new AccessPolicy.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/servicemesh"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := servicemesh.NewAccessPolicy(ctx, "test_access_policy", &servicemesh.AccessPolicyArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				MeshId:        pulumi.Any(testMesh.Id),
//				Name:          pulumi.Any(accessPolicyName),
//				Rules: servicemesh.AccessPolicyRuleArray{
//					&servicemesh.AccessPolicyRuleArgs{
//						Action: pulumi.Any(accessPolicyRulesAction),
//						Destination: &servicemesh.AccessPolicyRuleDestinationArgs{
//							Type:             pulumi.Any(accessPolicyRulesDestinationType),
//							Hostnames:        pulumi.Any(accessPolicyRulesDestinationHostnames),
//							IngressGatewayId: pulumi.Any(testIngressGateway.Id),
//							IpAddresses:      pulumi.Any(accessPolicyRulesDestinationIpAddresses),
//							Ports:            pulumi.Any(accessPolicyRulesDestinationPorts),
//							Protocol:         pulumi.Any(accessPolicyRulesDestinationProtocol),
//							VirtualServiceId: pulumi.Any(testVirtualService.Id),
//						},
//						Source: &servicemesh.AccessPolicyRuleSourceArgs{
//							Type:             pulumi.Any(accessPolicyRulesSourceType),
//							Hostnames:        pulumi.Any(accessPolicyRulesSourceHostnames),
//							IngressGatewayId: pulumi.Any(testIngressGateway.Id),
//							IpAddresses:      pulumi.Any(accessPolicyRulesSourceIpAddresses),
//							Ports:            pulumi.Any(accessPolicyRulesSourcePorts),
//							Protocol:         pulumi.Any(accessPolicyRulesSourceProtocol),
//							VirtualServiceId: pulumi.Any(testVirtualService.Id),
//						},
//					},
//				},
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				Description: pulumi.Any(accessPolicyDescription),
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// AccessPolicies can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:ServiceMesh/accessPolicy:AccessPolicy test_access_policy "id"
// ```
type AccessPolicy struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The OCID of the service mesh in which this access policy is created.
	MeshId pulumi.StringOutput `pulumi:"meshId"`
	// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
	Name pulumi.StringOutput `pulumi:"name"`
	// (Updatable) List of applicable rules
	Rules AccessPolicyRuleArrayOutput `pulumi:"rules"`
	// The current state of the Resource.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time when this resource was created in an RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time when this resource was updated in an RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewAccessPolicy registers a new resource with the given unique name, arguments, and options.
func NewAccessPolicy(ctx *pulumi.Context,
	name string, args *AccessPolicyArgs, opts ...pulumi.ResourceOption) (*AccessPolicy, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.MeshId == nil {
		return nil, errors.New("invalid value for required argument 'MeshId'")
	}
	if args.Rules == nil {
		return nil, errors.New("invalid value for required argument 'Rules'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource AccessPolicy
	err := ctx.RegisterResource("oci:ServiceMesh/accessPolicy:AccessPolicy", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetAccessPolicy gets an existing AccessPolicy resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetAccessPolicy(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *AccessPolicyState, opts ...pulumi.ResourceOption) (*AccessPolicy, error) {
	var resource AccessPolicy
	err := ctx.ReadResource("oci:ServiceMesh/accessPolicy:AccessPolicy", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering AccessPolicy resources.
type accessPolicyState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description *string `pulumi:"description"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The OCID of the service mesh in which this access policy is created.
	MeshId *string `pulumi:"meshId"`
	// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
	Name *string `pulumi:"name"`
	// (Updatable) List of applicable rules
	Rules []AccessPolicyRule `pulumi:"rules"`
	// The current state of the Resource.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time when this resource was created in an RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time when this resource was updated in an RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type AccessPolicyState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// The OCID of the service mesh in which this access policy is created.
	MeshId pulumi.StringPtrInput
	// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
	Name pulumi.StringPtrInput
	// (Updatable) List of applicable rules
	Rules AccessPolicyRuleArrayInput
	// The current state of the Resource.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The time when this resource was created in an RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time when this resource was updated in an RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (AccessPolicyState) ElementType() reflect.Type {
	return reflect.TypeOf((*accessPolicyState)(nil)).Elem()
}

type accessPolicyArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description *string `pulumi:"description"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The OCID of the service mesh in which this access policy is created.
	MeshId string `pulumi:"meshId"`
	// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
	Name *string `pulumi:"name"`
	// (Updatable) List of applicable rules
	Rules []AccessPolicyRule `pulumi:"rules"`
}

// The set of arguments for constructing a AccessPolicy resource.
type AccessPolicyArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// The OCID of the service mesh in which this access policy is created.
	MeshId pulumi.StringInput
	// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
	Name pulumi.StringPtrInput
	// (Updatable) List of applicable rules
	Rules AccessPolicyRuleArrayInput
}

func (AccessPolicyArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*accessPolicyArgs)(nil)).Elem()
}

type AccessPolicyInput interface {
	pulumi.Input

	ToAccessPolicyOutput() AccessPolicyOutput
	ToAccessPolicyOutputWithContext(ctx context.Context) AccessPolicyOutput
}

func (*AccessPolicy) ElementType() reflect.Type {
	return reflect.TypeOf((**AccessPolicy)(nil)).Elem()
}

func (i *AccessPolicy) ToAccessPolicyOutput() AccessPolicyOutput {
	return i.ToAccessPolicyOutputWithContext(context.Background())
}

func (i *AccessPolicy) ToAccessPolicyOutputWithContext(ctx context.Context) AccessPolicyOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AccessPolicyOutput)
}

// AccessPolicyArrayInput is an input type that accepts AccessPolicyArray and AccessPolicyArrayOutput values.
// You can construct a concrete instance of `AccessPolicyArrayInput` via:
//
//	AccessPolicyArray{ AccessPolicyArgs{...} }
type AccessPolicyArrayInput interface {
	pulumi.Input

	ToAccessPolicyArrayOutput() AccessPolicyArrayOutput
	ToAccessPolicyArrayOutputWithContext(context.Context) AccessPolicyArrayOutput
}

type AccessPolicyArray []AccessPolicyInput

func (AccessPolicyArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AccessPolicy)(nil)).Elem()
}

func (i AccessPolicyArray) ToAccessPolicyArrayOutput() AccessPolicyArrayOutput {
	return i.ToAccessPolicyArrayOutputWithContext(context.Background())
}

func (i AccessPolicyArray) ToAccessPolicyArrayOutputWithContext(ctx context.Context) AccessPolicyArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AccessPolicyArrayOutput)
}

// AccessPolicyMapInput is an input type that accepts AccessPolicyMap and AccessPolicyMapOutput values.
// You can construct a concrete instance of `AccessPolicyMapInput` via:
//
//	AccessPolicyMap{ "key": AccessPolicyArgs{...} }
type AccessPolicyMapInput interface {
	pulumi.Input

	ToAccessPolicyMapOutput() AccessPolicyMapOutput
	ToAccessPolicyMapOutputWithContext(context.Context) AccessPolicyMapOutput
}

type AccessPolicyMap map[string]AccessPolicyInput

func (AccessPolicyMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AccessPolicy)(nil)).Elem()
}

func (i AccessPolicyMap) ToAccessPolicyMapOutput() AccessPolicyMapOutput {
	return i.ToAccessPolicyMapOutputWithContext(context.Background())
}

func (i AccessPolicyMap) ToAccessPolicyMapOutputWithContext(ctx context.Context) AccessPolicyMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(AccessPolicyMapOutput)
}

type AccessPolicyOutput struct{ *pulumi.OutputState }

func (AccessPolicyOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**AccessPolicy)(nil)).Elem()
}

func (o AccessPolicyOutput) ToAccessPolicyOutput() AccessPolicyOutput {
	return o
}

func (o AccessPolicyOutput) ToAccessPolicyOutputWithContext(ctx context.Context) AccessPolicyOutput {
	return o
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o AccessPolicyOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *AccessPolicy) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o AccessPolicyOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *AccessPolicy) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
func (o AccessPolicyOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *AccessPolicy) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o AccessPolicyOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *AccessPolicy) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
func (o AccessPolicyOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *AccessPolicy) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The OCID of the service mesh in which this access policy is created.
func (o AccessPolicyOutput) MeshId() pulumi.StringOutput {
	return o.ApplyT(func(v *AccessPolicy) pulumi.StringOutput { return v.MeshId }).(pulumi.StringOutput)
}

// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
func (o AccessPolicyOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *AccessPolicy) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// (Updatable) List of applicable rules
func (o AccessPolicyOutput) Rules() AccessPolicyRuleArrayOutput {
	return o.ApplyT(func(v *AccessPolicy) AccessPolicyRuleArrayOutput { return v.Rules }).(AccessPolicyRuleArrayOutput)
}

// The current state of the Resource.
func (o AccessPolicyOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *AccessPolicy) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o AccessPolicyOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *AccessPolicy) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time when this resource was created in an RFC3339 formatted datetime string.
func (o AccessPolicyOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *AccessPolicy) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when this resource was updated in an RFC3339 formatted datetime string.
func (o AccessPolicyOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *AccessPolicy) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type AccessPolicyArrayOutput struct{ *pulumi.OutputState }

func (AccessPolicyArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*AccessPolicy)(nil)).Elem()
}

func (o AccessPolicyArrayOutput) ToAccessPolicyArrayOutput() AccessPolicyArrayOutput {
	return o
}

func (o AccessPolicyArrayOutput) ToAccessPolicyArrayOutputWithContext(ctx context.Context) AccessPolicyArrayOutput {
	return o
}

func (o AccessPolicyArrayOutput) Index(i pulumi.IntInput) AccessPolicyOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *AccessPolicy {
		return vs[0].([]*AccessPolicy)[vs[1].(int)]
	}).(AccessPolicyOutput)
}

type AccessPolicyMapOutput struct{ *pulumi.OutputState }

func (AccessPolicyMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*AccessPolicy)(nil)).Elem()
}

func (o AccessPolicyMapOutput) ToAccessPolicyMapOutput() AccessPolicyMapOutput {
	return o
}

func (o AccessPolicyMapOutput) ToAccessPolicyMapOutputWithContext(ctx context.Context) AccessPolicyMapOutput {
	return o
}

func (o AccessPolicyMapOutput) MapIndex(k pulumi.StringInput) AccessPolicyOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *AccessPolicy {
		return vs[0].(map[string]*AccessPolicy)[vs[1].(string)]
	}).(AccessPolicyOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*AccessPolicyInput)(nil)).Elem(), &AccessPolicy{})
	pulumi.RegisterInputType(reflect.TypeOf((*AccessPolicyArrayInput)(nil)).Elem(), AccessPolicyArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*AccessPolicyMapInput)(nil)).Elem(), AccessPolicyMap{})
	pulumi.RegisterOutputType(AccessPolicyOutput{})
	pulumi.RegisterOutputType(AccessPolicyArrayOutput{})
	pulumi.RegisterOutputType(AccessPolicyMapOutput{})
}
