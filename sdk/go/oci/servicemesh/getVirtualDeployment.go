// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package servicemesh

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v2/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Virtual Deployment resource in Oracle Cloud Infrastructure Service Mesh service.
//
// Gets a VirtualDeployment by identifier.
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
//			_, err := servicemesh.GetVirtualDeployment(ctx, &servicemesh.GetVirtualDeploymentArgs{
//				VirtualDeploymentId: testVirtualDeploymentOciServiceMeshVirtualDeployment.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupVirtualDeployment(ctx *pulumi.Context, args *LookupVirtualDeploymentArgs, opts ...pulumi.InvokeOption) (*LookupVirtualDeploymentResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupVirtualDeploymentResult
	err := ctx.Invoke("oci:ServiceMesh/getVirtualDeployment:getVirtualDeployment", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getVirtualDeployment.
type LookupVirtualDeploymentArgs struct {
	// Unique VirtualDeployment identifier.
	VirtualDeploymentId string `pulumi:"virtualDeploymentId"`
}

// A collection of values returned by getVirtualDeployment.
type LookupVirtualDeploymentResult struct {
	// This configuration determines if logging is enabled and where the logs will be output.
	AccessLoggings []GetVirtualDeploymentAccessLogging `pulumi:"accessLoggings"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
	Description string `pulumi:"description"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// Unique identifier that is immutable on creation.
	Id string `pulumi:"id"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// The listeners for the virtual deployment
	Listeners []GetVirtualDeploymentListener `pulumi:"listeners"`
	// A user-friendly name. The name must be unique within the same virtual service and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
	Name string `pulumi:"name"`
	// Service Discovery configuration for virtual deployments.
	ServiceDiscoveries []GetVirtualDeploymentServiceDiscovery `pulumi:"serviceDiscoveries"`
	// The current state of the Resource.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time when this resource was created in an RFC3339 formatted datetime string.
	TimeCreated string `pulumi:"timeCreated"`
	// The time when this resource was updated in an RFC3339 formatted datetime string.
	TimeUpdated         string `pulumi:"timeUpdated"`
	VirtualDeploymentId string `pulumi:"virtualDeploymentId"`
	// The OCID of the virtual service in which this virtual deployment is created.
	VirtualServiceId string `pulumi:"virtualServiceId"`
}

func LookupVirtualDeploymentOutput(ctx *pulumi.Context, args LookupVirtualDeploymentOutputArgs, opts ...pulumi.InvokeOption) LookupVirtualDeploymentResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupVirtualDeploymentResultOutput, error) {
			args := v.(LookupVirtualDeploymentArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ServiceMesh/getVirtualDeployment:getVirtualDeployment", args, LookupVirtualDeploymentResultOutput{}, options).(LookupVirtualDeploymentResultOutput), nil
		}).(LookupVirtualDeploymentResultOutput)
}

// A collection of arguments for invoking getVirtualDeployment.
type LookupVirtualDeploymentOutputArgs struct {
	// Unique VirtualDeployment identifier.
	VirtualDeploymentId pulumi.StringInput `pulumi:"virtualDeploymentId"`
}

func (LookupVirtualDeploymentOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupVirtualDeploymentArgs)(nil)).Elem()
}

// A collection of values returned by getVirtualDeployment.
type LookupVirtualDeploymentResultOutput struct{ *pulumi.OutputState }

func (LookupVirtualDeploymentResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupVirtualDeploymentResult)(nil)).Elem()
}

func (o LookupVirtualDeploymentResultOutput) ToLookupVirtualDeploymentResultOutput() LookupVirtualDeploymentResultOutput {
	return o
}

func (o LookupVirtualDeploymentResultOutput) ToLookupVirtualDeploymentResultOutputWithContext(ctx context.Context) LookupVirtualDeploymentResultOutput {
	return o
}

// This configuration determines if logging is enabled and where the logs will be output.
func (o LookupVirtualDeploymentResultOutput) AccessLoggings() GetVirtualDeploymentAccessLoggingArrayOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) []GetVirtualDeploymentAccessLogging { return v.AccessLoggings }).(GetVirtualDeploymentAccessLoggingArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
func (o LookupVirtualDeploymentResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupVirtualDeploymentResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Description of the resource. It can be changed after creation. Avoid entering confidential information.  Example: `This is my new resource`
func (o LookupVirtualDeploymentResultOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) string { return v.Description }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupVirtualDeploymentResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// Unique identifier that is immutable on creation.
func (o LookupVirtualDeploymentResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) string { return v.Id }).(pulumi.StringOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
func (o LookupVirtualDeploymentResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// The listeners for the virtual deployment
func (o LookupVirtualDeploymentResultOutput) Listeners() GetVirtualDeploymentListenerArrayOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) []GetVirtualDeploymentListener { return v.Listeners }).(GetVirtualDeploymentListenerArrayOutput)
}

// A user-friendly name. The name must be unique within the same virtual service and cannot be changed after creation. Avoid entering confidential information.  Example: `My unique resource name`
func (o LookupVirtualDeploymentResultOutput) Name() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) string { return v.Name }).(pulumi.StringOutput)
}

// Service Discovery configuration for virtual deployments.
func (o LookupVirtualDeploymentResultOutput) ServiceDiscoveries() GetVirtualDeploymentServiceDiscoveryArrayOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) []GetVirtualDeploymentServiceDiscovery {
		return v.ServiceDiscoveries
	}).(GetVirtualDeploymentServiceDiscoveryArrayOutput)
}

// The current state of the Resource.
func (o LookupVirtualDeploymentResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupVirtualDeploymentResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time when this resource was created in an RFC3339 formatted datetime string.
func (o LookupVirtualDeploymentResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time when this resource was updated in an RFC3339 formatted datetime string.
func (o LookupVirtualDeploymentResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func (o LookupVirtualDeploymentResultOutput) VirtualDeploymentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) string { return v.VirtualDeploymentId }).(pulumi.StringOutput)
}

// The OCID of the virtual service in which this virtual deployment is created.
func (o LookupVirtualDeploymentResultOutput) VirtualServiceId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVirtualDeploymentResult) string { return v.VirtualServiceId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupVirtualDeploymentResultOutput{})
}
