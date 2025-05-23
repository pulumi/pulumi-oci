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

// This resource provides the Virtual Service resource in Oracle Cloud Infrastructure Service Mesh service.
//
// Creates a new VirtualService.
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
//			_, err := servicemesh.NewVirtualService(ctx, "test_virtual_service", &servicemesh.VirtualServiceArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				MeshId:        pulumi.Any(testMesh.Id),
//				Name:          pulumi.Any(virtualServiceName),
//				DefaultRoutingPolicy: &servicemesh.VirtualServiceDefaultRoutingPolicyArgs{
//					Type: pulumi.Any(virtualServiceDefaultRoutingPolicyType),
//				},
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				Description: pulumi.Any(virtualServiceDescription),
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//				Hosts: pulumi.Any(virtualServiceHosts),
//				Mtls: &servicemesh.VirtualServiceMtlsArgs{
//					Mode:            pulumi.Any(virtualServiceMtlsMode),
//					MaximumValidity: pulumi.Any(virtualServiceMtlsMaximumValidity),
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
// VirtualServices can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:ServiceMesh/virtualService:VirtualService test_virtual_service "id"
// ```
type VirtualService struct {
	pulumi.CustomResourceState

	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Routing policy for the virtual service.
	DefaultRoutingPolicy VirtualServiceDefaultRoutingPolicyOutput `pulumi:"defaultRoutingPolicy"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", "*.example.com", "*.com". Can be omitted if the virtual service will only have TCP virtual deployments.
	Hosts pulumi.StringArrayOutput `pulumi:"hosts"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// The OCID of the service mesh in which this virtual service is created.
	MeshId pulumi.StringOutput `pulumi:"meshId"`
	// (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
	Mtls VirtualServiceMtlsOutput `pulumi:"mtls"`
	// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name pulumi.StringOutput `pulumi:"name"`
	// The current state of the Resource.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time when this resource was created in an RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time when this resource was updated in an RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewVirtualService registers a new resource with the given unique name, arguments, and options.
func NewVirtualService(ctx *pulumi.Context,
	name string, args *VirtualServiceArgs, opts ...pulumi.ResourceOption) (*VirtualService, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.MeshId == nil {
		return nil, errors.New("invalid value for required argument 'MeshId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource VirtualService
	err := ctx.RegisterResource("oci:ServiceMesh/virtualService:VirtualService", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetVirtualService gets an existing VirtualService resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetVirtualService(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *VirtualServiceState, opts ...pulumi.ResourceOption) (*VirtualService, error) {
	var resource VirtualService
	err := ctx.ReadResource("oci:ServiceMesh/virtualService:VirtualService", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering VirtualService resources.
type virtualServiceState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Routing policy for the virtual service.
	DefaultRoutingPolicy *VirtualServiceDefaultRoutingPolicy `pulumi:"defaultRoutingPolicy"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description *string `pulumi:"description"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", "*.example.com", "*.com". Can be omitted if the virtual service will only have TCP virtual deployments.
	Hosts []string `pulumi:"hosts"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// The OCID of the service mesh in which this virtual service is created.
	MeshId *string `pulumi:"meshId"`
	// (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
	Mtls *VirtualServiceMtls `pulumi:"mtls"`
	// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name *string `pulumi:"name"`
	// The current state of the Resource.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time when this resource was created in an RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time when this resource was updated in an RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type VirtualServiceState struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Routing policy for the virtual service.
	DefaultRoutingPolicy VirtualServiceDefaultRoutingPolicyPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", "*.example.com", "*.com". Can be omitted if the virtual service will only have TCP virtual deployments.
	Hosts pulumi.StringArrayInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// The OCID of the service mesh in which this virtual service is created.
	MeshId pulumi.StringPtrInput
	// (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
	Mtls VirtualServiceMtlsPtrInput
	// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name pulumi.StringPtrInput
	// The current state of the Resource.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The time when this resource was created in an RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time when this resource was updated in an RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (VirtualServiceState) ElementType() reflect.Type {
	return reflect.TypeOf((*virtualServiceState)(nil)).Elem()
}

type virtualServiceArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Routing policy for the virtual service.
	DefaultRoutingPolicy *VirtualServiceDefaultRoutingPolicy `pulumi:"defaultRoutingPolicy"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description *string `pulumi:"description"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", "*.example.com", "*.com". Can be omitted if the virtual service will only have TCP virtual deployments.
	Hosts []string `pulumi:"hosts"`
	// The OCID of the service mesh in which this virtual service is created.
	MeshId string `pulumi:"meshId"`
	// (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
	Mtls *VirtualServiceMtls `pulumi:"mtls"`
	// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name *string `pulumi:"name"`
}

// The set of arguments for constructing a VirtualService resource.
type VirtualServiceArgs struct {
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput
	// (Updatable) Routing policy for the virtual service.
	DefaultRoutingPolicy VirtualServiceDefaultRoutingPolicyPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", "*.example.com", "*.com". Can be omitted if the virtual service will only have TCP virtual deployments.
	Hosts pulumi.StringArrayInput
	// The OCID of the service mesh in which this virtual service is created.
	MeshId pulumi.StringInput
	// (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
	Mtls VirtualServiceMtlsPtrInput
	// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Name pulumi.StringPtrInput
}

func (VirtualServiceArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*virtualServiceArgs)(nil)).Elem()
}

type VirtualServiceInput interface {
	pulumi.Input

	ToVirtualServiceOutput() VirtualServiceOutput
	ToVirtualServiceOutputWithContext(ctx context.Context) VirtualServiceOutput
}

func (*VirtualService) ElementType() reflect.Type {
	return reflect.TypeOf((**VirtualService)(nil)).Elem()
}

func (i *VirtualService) ToVirtualServiceOutput() VirtualServiceOutput {
	return i.ToVirtualServiceOutputWithContext(context.Background())
}

func (i *VirtualService) ToVirtualServiceOutputWithContext(ctx context.Context) VirtualServiceOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VirtualServiceOutput)
}

// VirtualServiceArrayInput is an input type that accepts VirtualServiceArray and VirtualServiceArrayOutput values.
// You can construct a concrete instance of `VirtualServiceArrayInput` via:
//
//	VirtualServiceArray{ VirtualServiceArgs{...} }
type VirtualServiceArrayInput interface {
	pulumi.Input

	ToVirtualServiceArrayOutput() VirtualServiceArrayOutput
	ToVirtualServiceArrayOutputWithContext(context.Context) VirtualServiceArrayOutput
}

type VirtualServiceArray []VirtualServiceInput

func (VirtualServiceArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*VirtualService)(nil)).Elem()
}

func (i VirtualServiceArray) ToVirtualServiceArrayOutput() VirtualServiceArrayOutput {
	return i.ToVirtualServiceArrayOutputWithContext(context.Background())
}

func (i VirtualServiceArray) ToVirtualServiceArrayOutputWithContext(ctx context.Context) VirtualServiceArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VirtualServiceArrayOutput)
}

// VirtualServiceMapInput is an input type that accepts VirtualServiceMap and VirtualServiceMapOutput values.
// You can construct a concrete instance of `VirtualServiceMapInput` via:
//
//	VirtualServiceMap{ "key": VirtualServiceArgs{...} }
type VirtualServiceMapInput interface {
	pulumi.Input

	ToVirtualServiceMapOutput() VirtualServiceMapOutput
	ToVirtualServiceMapOutputWithContext(context.Context) VirtualServiceMapOutput
}

type VirtualServiceMap map[string]VirtualServiceInput

func (VirtualServiceMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*VirtualService)(nil)).Elem()
}

func (i VirtualServiceMap) ToVirtualServiceMapOutput() VirtualServiceMapOutput {
	return i.ToVirtualServiceMapOutputWithContext(context.Background())
}

func (i VirtualServiceMap) ToVirtualServiceMapOutputWithContext(ctx context.Context) VirtualServiceMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(VirtualServiceMapOutput)
}

type VirtualServiceOutput struct{ *pulumi.OutputState }

func (VirtualServiceOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**VirtualService)(nil)).Elem()
}

func (o VirtualServiceOutput) ToVirtualServiceOutput() VirtualServiceOutput {
	return o
}

func (o VirtualServiceOutput) ToVirtualServiceOutputWithContext(ctx context.Context) VirtualServiceOutput {
	return o
}

// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o VirtualServiceOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *VirtualService) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Routing policy for the virtual service.
func (o VirtualServiceOutput) DefaultRoutingPolicy() VirtualServiceDefaultRoutingPolicyOutput {
	return o.ApplyT(func(v *VirtualService) VirtualServiceDefaultRoutingPolicyOutput { return v.DefaultRoutingPolicy }).(VirtualServiceDefaultRoutingPolicyOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o VirtualServiceOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *VirtualService) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
func (o VirtualServiceOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *VirtualService) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o VirtualServiceOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *VirtualService) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// (Updatable) The DNS hostnames of the virtual service that is used by its callers. Wildcard hostnames are supported in the prefix form. Examples of valid hostnames are "www.example.com", "*.example.com", "*.com". Can be omitted if the virtual service will only have TCP virtual deployments.
func (o VirtualServiceOutput) Hosts() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *VirtualService) pulumi.StringArrayOutput { return v.Hosts }).(pulumi.StringArrayOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
func (o VirtualServiceOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v *VirtualService) pulumi.StringOutput { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The OCID of the service mesh in which this virtual service is created.
func (o VirtualServiceOutput) MeshId() pulumi.StringOutput {
	return o.ApplyT(func(v *VirtualService) pulumi.StringOutput { return v.MeshId }).(pulumi.StringOutput)
}

// (Updatable) The mTLS authentication mode to use when receiving requests from other virtual services or ingress gateways within the mesh.
func (o VirtualServiceOutput) Mtls() VirtualServiceMtlsOutput {
	return o.ApplyT(func(v *VirtualService) VirtualServiceMtlsOutput { return v.Mtls }).(VirtualServiceMtlsOutput)
}

// A user-friendly name. The name has to be unique within the same service mesh and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o VirtualServiceOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v *VirtualService) pulumi.StringOutput { return v.Name }).(pulumi.StringOutput)
}

// The current state of the Resource.
func (o VirtualServiceOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *VirtualService) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o VirtualServiceOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *VirtualService) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time when this resource was created in an RFC3339 formatted datetime string.
func (o VirtualServiceOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *VirtualService) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when this resource was updated in an RFC3339 formatted datetime string.
func (o VirtualServiceOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *VirtualService) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type VirtualServiceArrayOutput struct{ *pulumi.OutputState }

func (VirtualServiceArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*VirtualService)(nil)).Elem()
}

func (o VirtualServiceArrayOutput) ToVirtualServiceArrayOutput() VirtualServiceArrayOutput {
	return o
}

func (o VirtualServiceArrayOutput) ToVirtualServiceArrayOutputWithContext(ctx context.Context) VirtualServiceArrayOutput {
	return o
}

func (o VirtualServiceArrayOutput) Index(i pulumi.IntInput) VirtualServiceOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *VirtualService {
		return vs[0].([]*VirtualService)[vs[1].(int)]
	}).(VirtualServiceOutput)
}

type VirtualServiceMapOutput struct{ *pulumi.OutputState }

func (VirtualServiceMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*VirtualService)(nil)).Elem()
}

func (o VirtualServiceMapOutput) ToVirtualServiceMapOutput() VirtualServiceMapOutput {
	return o
}

func (o VirtualServiceMapOutput) ToVirtualServiceMapOutputWithContext(ctx context.Context) VirtualServiceMapOutput {
	return o
}

func (o VirtualServiceMapOutput) MapIndex(k pulumi.StringInput) VirtualServiceOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *VirtualService {
		return vs[0].(map[string]*VirtualService)[vs[1].(string)]
	}).(VirtualServiceOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*VirtualServiceInput)(nil)).Elem(), &VirtualService{})
	pulumi.RegisterInputType(reflect.TypeOf((*VirtualServiceArrayInput)(nil)).Elem(), VirtualServiceArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*VirtualServiceMapInput)(nil)).Elem(), VirtualServiceMap{})
	pulumi.RegisterOutputType(VirtualServiceOutput{})
	pulumi.RegisterOutputType(VirtualServiceArrayOutput{})
	pulumi.RegisterOutputType(VirtualServiceMapOutput{})
}
