// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package vnmonitoring

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Path Analyzer Test resource in Oracle Cloud Infrastructure Vn Monitoring service.
//
// Gets a `PathAnalyzerTest` using its identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/vnmonitoring"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := vnmonitoring.GetPathAnalyzerTest(ctx, &vnmonitoring.GetPathAnalyzerTestArgs{
//				PathAnalyzerTestId: testPathAnalyzerTestOciVnMonitoringPathAnalyzerTest.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupPathAnalyzerTest(ctx *pulumi.Context, args *LookupPathAnalyzerTestArgs, opts ...pulumi.InvokeOption) (*LookupPathAnalyzerTestResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupPathAnalyzerTestResult
	err := ctx.Invoke("oci:VnMonitoring/getPathAnalyzerTest:GetPathAnalyzerTest", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetPathAnalyzerTest.
type LookupPathAnalyzerTestArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource.
	PathAnalyzerTestId string `pulumi:"pathAnalyzerTestId"`
}

// A collection of values returned by GetPathAnalyzerTest.
type LookupPathAnalyzerTestResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource's compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// Information describing a source or destination in a `PathAnalyzerTest` resource.
	DestinationEndpoints []GetPathAnalyzerTestDestinationEndpoint `pulumi:"destinationEndpoints"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// A unique identifier established when the resource is created. The identifier can't be changed later.
	Id                 string `pulumi:"id"`
	PathAnalyzerTestId string `pulumi:"pathAnalyzerTestId"`
	// The IP protocol to use for the `PathAnalyzerTest` resource.
	Protocol int `pulumi:"protocol"`
	// Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
	ProtocolParameters []GetPathAnalyzerTestProtocolParameter `pulumi:"protocolParameters"`
	// Defines the query options required for a `PathAnalyzerTest` resource.
	QueryOptions []GetPathAnalyzerTestQueryOption `pulumi:"queryOptions"`
	// Information describing a source or destination in a `PathAnalyzerTest` resource.
	SourceEndpoints []GetPathAnalyzerTestSourceEndpoint `pulumi:"sourceEndpoints"`
	// The current state of the `PathAnalyzerTest` resource.
	State string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the `PathAnalyzerTest` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeCreated string `pulumi:"timeCreated"`
	// The date and time the `PathAnalyzerTest` resource was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupPathAnalyzerTestOutput(ctx *pulumi.Context, args LookupPathAnalyzerTestOutputArgs, opts ...pulumi.InvokeOption) LookupPathAnalyzerTestResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupPathAnalyzerTestResultOutput, error) {
			args := v.(LookupPathAnalyzerTestArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:VnMonitoring/getPathAnalyzerTest:GetPathAnalyzerTest", args, LookupPathAnalyzerTestResultOutput{}, options).(LookupPathAnalyzerTestResultOutput), nil
		}).(LookupPathAnalyzerTestResultOutput)
}

// A collection of arguments for invoking GetPathAnalyzerTest.
type LookupPathAnalyzerTestOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource.
	PathAnalyzerTestId pulumi.StringInput `pulumi:"pathAnalyzerTestId"`
}

func (LookupPathAnalyzerTestOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupPathAnalyzerTestArgs)(nil)).Elem()
}

// A collection of values returned by GetPathAnalyzerTest.
type LookupPathAnalyzerTestResultOutput struct{ *pulumi.OutputState }

func (LookupPathAnalyzerTestResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupPathAnalyzerTestResult)(nil)).Elem()
}

func (o LookupPathAnalyzerTestResultOutput) ToLookupPathAnalyzerTestResultOutput() LookupPathAnalyzerTestResultOutput {
	return o
}

func (o LookupPathAnalyzerTestResultOutput) ToLookupPathAnalyzerTestResultOutputWithContext(ctx context.Context) LookupPathAnalyzerTestResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource's compartment.
func (o LookupPathAnalyzerTestResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o LookupPathAnalyzerTestResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// Information describing a source or destination in a `PathAnalyzerTest` resource.
func (o LookupPathAnalyzerTestResultOutput) DestinationEndpoints() GetPathAnalyzerTestDestinationEndpointArrayOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) []GetPathAnalyzerTestDestinationEndpoint {
		return v.DestinationEndpoints
	}).(GetPathAnalyzerTestDestinationEndpointArrayOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o LookupPathAnalyzerTestResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o LookupPathAnalyzerTestResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// A unique identifier established when the resource is created. The identifier can't be changed later.
func (o LookupPathAnalyzerTestResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o LookupPathAnalyzerTestResultOutput) PathAnalyzerTestId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) string { return v.PathAnalyzerTestId }).(pulumi.StringOutput)
}

// The IP protocol to use for the `PathAnalyzerTest` resource.
func (o LookupPathAnalyzerTestResultOutput) Protocol() pulumi.IntOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) int { return v.Protocol }).(pulumi.IntOutput)
}

// Defines the IP protocol parameters for a `PathAnalyzerTest` resource.
func (o LookupPathAnalyzerTestResultOutput) ProtocolParameters() GetPathAnalyzerTestProtocolParameterArrayOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) []GetPathAnalyzerTestProtocolParameter {
		return v.ProtocolParameters
	}).(GetPathAnalyzerTestProtocolParameterArrayOutput)
}

// Defines the query options required for a `PathAnalyzerTest` resource.
func (o LookupPathAnalyzerTestResultOutput) QueryOptions() GetPathAnalyzerTestQueryOptionArrayOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) []GetPathAnalyzerTestQueryOption { return v.QueryOptions }).(GetPathAnalyzerTestQueryOptionArrayOutput)
}

// Information describing a source or destination in a `PathAnalyzerTest` resource.
func (o LookupPathAnalyzerTestResultOutput) SourceEndpoints() GetPathAnalyzerTestSourceEndpointArrayOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) []GetPathAnalyzerTestSourceEndpoint { return v.SourceEndpoints }).(GetPathAnalyzerTestSourceEndpointArrayOutput)
}

// The current state of the `PathAnalyzerTest` resource.
func (o LookupPathAnalyzerTestResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) string { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o LookupPathAnalyzerTestResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the `PathAnalyzerTest` resource was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o LookupPathAnalyzerTestResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the `PathAnalyzerTest` resource was last updated, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
func (o LookupPathAnalyzerTestResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupPathAnalyzerTestResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupPathAnalyzerTestResultOutput{})
}
