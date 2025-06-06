// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package integration

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Integration Instances in Oracle Cloud Infrastructure Integration service.
//
// Returns a list of Integration Instances.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/integration"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := integration.GetIntegrationInstances(ctx, &integration.GetIntegrationInstancesArgs{
//				CompartmentId: compartmentId,
//				DisplayName:   pulumi.StringRef(integrationInstanceDisplayName),
//				State:         pulumi.StringRef(integrationInstanceState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetIntegrationInstances(ctx *pulumi.Context, args *GetIntegrationInstancesArgs, opts ...pulumi.InvokeOption) (*GetIntegrationInstancesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetIntegrationInstancesResult
	err := ctx.Invoke("oci:Integration/getIntegrationInstances:getIntegrationInstances", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getIntegrationInstances.
type GetIntegrationInstancesArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
	DisplayName *string                         `pulumi:"displayName"`
	Filters     []GetIntegrationInstancesFilter `pulumi:"filters"`
	// Life cycle state to query on.
	State *string `pulumi:"state"`
}

// A collection of values returned by getIntegrationInstances.
type GetIntegrationInstancesResult struct {
	// Compartment Identifier.
	CompartmentId string `pulumi:"compartmentId"`
	// Integration Instance Identifier, can be renamed.
	DisplayName *string                         `pulumi:"displayName"`
	Filters     []GetIntegrationInstancesFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of integration_instances.
	IntegrationInstances []GetIntegrationInstancesIntegrationInstance `pulumi:"integrationInstances"`
	// The current state of the integration instance.
	State *string `pulumi:"state"`
}

func GetIntegrationInstancesOutput(ctx *pulumi.Context, args GetIntegrationInstancesOutputArgs, opts ...pulumi.InvokeOption) GetIntegrationInstancesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetIntegrationInstancesResultOutput, error) {
			args := v.(GetIntegrationInstancesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Integration/getIntegrationInstances:getIntegrationInstances", args, GetIntegrationInstancesResultOutput{}, options).(GetIntegrationInstancesResultOutput), nil
		}).(GetIntegrationInstancesResultOutput)
}

// A collection of arguments for invoking getIntegrationInstances.
type GetIntegrationInstancesOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
	DisplayName pulumi.StringPtrInput                   `pulumi:"displayName"`
	Filters     GetIntegrationInstancesFilterArrayInput `pulumi:"filters"`
	// Life cycle state to query on.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetIntegrationInstancesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetIntegrationInstancesArgs)(nil)).Elem()
}

// A collection of values returned by getIntegrationInstances.
type GetIntegrationInstancesResultOutput struct{ *pulumi.OutputState }

func (GetIntegrationInstancesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetIntegrationInstancesResult)(nil)).Elem()
}

func (o GetIntegrationInstancesResultOutput) ToGetIntegrationInstancesResultOutput() GetIntegrationInstancesResultOutput {
	return o
}

func (o GetIntegrationInstancesResultOutput) ToGetIntegrationInstancesResultOutputWithContext(ctx context.Context) GetIntegrationInstancesResultOutput {
	return o
}

// Compartment Identifier.
func (o GetIntegrationInstancesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetIntegrationInstancesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Integration Instance Identifier, can be renamed.
func (o GetIntegrationInstancesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetIntegrationInstancesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetIntegrationInstancesResultOutput) Filters() GetIntegrationInstancesFilterArrayOutput {
	return o.ApplyT(func(v GetIntegrationInstancesResult) []GetIntegrationInstancesFilter { return v.Filters }).(GetIntegrationInstancesFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetIntegrationInstancesResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetIntegrationInstancesResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of integration_instances.
func (o GetIntegrationInstancesResultOutput) IntegrationInstances() GetIntegrationInstancesIntegrationInstanceArrayOutput {
	return o.ApplyT(func(v GetIntegrationInstancesResult) []GetIntegrationInstancesIntegrationInstance {
		return v.IntegrationInstances
	}).(GetIntegrationInstancesIntegrationInstanceArrayOutput)
}

// The current state of the integration instance.
func (o GetIntegrationInstancesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetIntegrationInstancesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetIntegrationInstancesResultOutput{})
}
