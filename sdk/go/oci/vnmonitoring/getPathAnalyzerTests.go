// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package vnmonitoring

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Path Analyzer Tests in Oracle Cloud Infrastructure Vn Monitoring service.
//
// Returns a list of all `PathAnalyzerTests` in a compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/VnMonitoring"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := VnMonitoring.GetPathAnalyzerTests(ctx, &vnmonitoring.GetPathAnalyzerTestsArgs{
//				CompartmentId: _var.Compartment_id,
//				DisplayName:   pulumi.StringRef(_var.Path_analyzer_test_display_name),
//				State:         pulumi.StringRef(_var.Path_analyzer_test_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetPathAnalyzerTests(ctx *pulumi.Context, args *GetPathAnalyzerTestsArgs, opts ...pulumi.InvokeOption) (*GetPathAnalyzerTestsResult, error) {
	var rv GetPathAnalyzerTestsResult
	err := ctx.Invoke("oci:VnMonitoring/getPathAnalyzerTests:GetPathAnalyzerTests", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking GetPathAnalyzerTests.
type GetPathAnalyzerTestsArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter that returns only resources that match the entire display name given.
	DisplayName *string                      `pulumi:"displayName"`
	Filters     []GetPathAnalyzerTestsFilter `pulumi:"filters"`
	// A filter that returns only resources whose `lifecycleState` matches the given `lifecycleState`.
	State *string `pulumi:"state"`
}

// A collection of values returned by GetPathAnalyzerTests.
type GetPathAnalyzerTestsResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource's compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName *string                      `pulumi:"displayName"`
	Filters     []GetPathAnalyzerTestsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The list of path_analyzer_test_collection.
	PathAnalyzerTestCollections []GetPathAnalyzerTestsPathAnalyzerTestCollection `pulumi:"pathAnalyzerTestCollections"`
	// The current state of the `PathAnalyzerTest` resource.
	State *string `pulumi:"state"`
}

func GetPathAnalyzerTestsOutput(ctx *pulumi.Context, args GetPathAnalyzerTestsOutputArgs, opts ...pulumi.InvokeOption) GetPathAnalyzerTestsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetPathAnalyzerTestsResult, error) {
			args := v.(GetPathAnalyzerTestsArgs)
			r, err := GetPathAnalyzerTests(ctx, &args, opts...)
			var s GetPathAnalyzerTestsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetPathAnalyzerTestsResultOutput)
}

// A collection of arguments for invoking GetPathAnalyzerTests.
type GetPathAnalyzerTestsOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter that returns only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput                `pulumi:"displayName"`
	Filters     GetPathAnalyzerTestsFilterArrayInput `pulumi:"filters"`
	// A filter that returns only resources whose `lifecycleState` matches the given `lifecycleState`.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetPathAnalyzerTestsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPathAnalyzerTestsArgs)(nil)).Elem()
}

// A collection of values returned by GetPathAnalyzerTests.
type GetPathAnalyzerTestsResultOutput struct{ *pulumi.OutputState }

func (GetPathAnalyzerTestsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetPathAnalyzerTestsResult)(nil)).Elem()
}

func (o GetPathAnalyzerTestsResultOutput) ToGetPathAnalyzerTestsResultOutput() GetPathAnalyzerTestsResultOutput {
	return o
}

func (o GetPathAnalyzerTestsResultOutput) ToGetPathAnalyzerTestsResultOutputWithContext(ctx context.Context) GetPathAnalyzerTestsResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the `PathAnalyzerTest` resource's compartment.
func (o GetPathAnalyzerTestsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetPathAnalyzerTestsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o GetPathAnalyzerTestsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPathAnalyzerTestsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetPathAnalyzerTestsResultOutput) Filters() GetPathAnalyzerTestsFilterArrayOutput {
	return o.ApplyT(func(v GetPathAnalyzerTestsResult) []GetPathAnalyzerTestsFilter { return v.Filters }).(GetPathAnalyzerTestsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetPathAnalyzerTestsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetPathAnalyzerTestsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The list of path_analyzer_test_collection.
func (o GetPathAnalyzerTestsResultOutput) PathAnalyzerTestCollections() GetPathAnalyzerTestsPathAnalyzerTestCollectionArrayOutput {
	return o.ApplyT(func(v GetPathAnalyzerTestsResult) []GetPathAnalyzerTestsPathAnalyzerTestCollection {
		return v.PathAnalyzerTestCollections
	}).(GetPathAnalyzerTestsPathAnalyzerTestCollectionArrayOutput)
}

// The current state of the `PathAnalyzerTest` resource.
func (o GetPathAnalyzerTestsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetPathAnalyzerTestsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetPathAnalyzerTestsResultOutput{})
}