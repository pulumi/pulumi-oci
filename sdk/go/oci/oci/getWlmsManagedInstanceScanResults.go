// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package oci

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Managed Instance Scan Results in Oracle Cloud Infrastructure Wlms service.
//
// Gets all the scan results for all WebLogic servers in the managed instance.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/oci"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := oci.GetWlmsManagedInstanceScanResults(ctx, &oci.GetWlmsManagedInstanceScanResultsArgs{
//				ManagedInstanceId: testManagedInstance.Id,
//				ServerName:        pulumi.StringRef(managedInstanceScanResultServerName),
//				WlsDomainId:       pulumi.StringRef(testWlsDomain.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetWlmsManagedInstanceScanResults(ctx *pulumi.Context, args *GetWlmsManagedInstanceScanResultsArgs, opts ...pulumi.InvokeOption) (*GetWlmsManagedInstanceScanResultsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetWlmsManagedInstanceScanResultsResult
	err := ctx.Invoke("oci:oci/getWlmsManagedInstanceScanResults:getWlmsManagedInstanceScanResults", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getWlmsManagedInstanceScanResults.
type GetWlmsManagedInstanceScanResultsArgs struct {
	Filters []GetWlmsManagedInstanceScanResultsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
	ManagedInstanceId string `pulumi:"managedInstanceId"`
	// The name of the server.
	ServerName *string `pulumi:"serverName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
	WlsDomainId *string `pulumi:"wlsDomainId"`
}

// A collection of values returned by getWlmsManagedInstanceScanResults.
type GetWlmsManagedInstanceScanResultsResult struct {
	Filters []GetWlmsManagedInstanceScanResultsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id                string `pulumi:"id"`
	ManagedInstanceId string `pulumi:"managedInstanceId"`
	// The list of scan_result_collection.
	ScanResultCollections []GetWlmsManagedInstanceScanResultsScanResultCollection `pulumi:"scanResultCollections"`
	// The name of the WebLogic server to which the server check belongs.
	ServerName *string `pulumi:"serverName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
	WlsDomainId *string `pulumi:"wlsDomainId"`
}

func GetWlmsManagedInstanceScanResultsOutput(ctx *pulumi.Context, args GetWlmsManagedInstanceScanResultsOutputArgs, opts ...pulumi.InvokeOption) GetWlmsManagedInstanceScanResultsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetWlmsManagedInstanceScanResultsResultOutput, error) {
			args := v.(GetWlmsManagedInstanceScanResultsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:oci/getWlmsManagedInstanceScanResults:getWlmsManagedInstanceScanResults", args, GetWlmsManagedInstanceScanResultsResultOutput{}, options).(GetWlmsManagedInstanceScanResultsResultOutput), nil
		}).(GetWlmsManagedInstanceScanResultsResultOutput)
}

// A collection of arguments for invoking getWlmsManagedInstanceScanResults.
type GetWlmsManagedInstanceScanResultsOutputArgs struct {
	Filters GetWlmsManagedInstanceScanResultsFilterArrayInput `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the instance.
	ManagedInstanceId pulumi.StringInput `pulumi:"managedInstanceId"`
	// The name of the server.
	ServerName pulumi.StringPtrInput `pulumi:"serverName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
	WlsDomainId pulumi.StringPtrInput `pulumi:"wlsDomainId"`
}

func (GetWlmsManagedInstanceScanResultsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetWlmsManagedInstanceScanResultsArgs)(nil)).Elem()
}

// A collection of values returned by getWlmsManagedInstanceScanResults.
type GetWlmsManagedInstanceScanResultsResultOutput struct{ *pulumi.OutputState }

func (GetWlmsManagedInstanceScanResultsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetWlmsManagedInstanceScanResultsResult)(nil)).Elem()
}

func (o GetWlmsManagedInstanceScanResultsResultOutput) ToGetWlmsManagedInstanceScanResultsResultOutput() GetWlmsManagedInstanceScanResultsResultOutput {
	return o
}

func (o GetWlmsManagedInstanceScanResultsResultOutput) ToGetWlmsManagedInstanceScanResultsResultOutputWithContext(ctx context.Context) GetWlmsManagedInstanceScanResultsResultOutput {
	return o
}

func (o GetWlmsManagedInstanceScanResultsResultOutput) Filters() GetWlmsManagedInstanceScanResultsFilterArrayOutput {
	return o.ApplyT(func(v GetWlmsManagedInstanceScanResultsResult) []GetWlmsManagedInstanceScanResultsFilter {
		return v.Filters
	}).(GetWlmsManagedInstanceScanResultsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetWlmsManagedInstanceScanResultsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetWlmsManagedInstanceScanResultsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetWlmsManagedInstanceScanResultsResultOutput) ManagedInstanceId() pulumi.StringOutput {
	return o.ApplyT(func(v GetWlmsManagedInstanceScanResultsResult) string { return v.ManagedInstanceId }).(pulumi.StringOutput)
}

// The list of scan_result_collection.
func (o GetWlmsManagedInstanceScanResultsResultOutput) ScanResultCollections() GetWlmsManagedInstanceScanResultsScanResultCollectionArrayOutput {
	return o.ApplyT(func(v GetWlmsManagedInstanceScanResultsResult) []GetWlmsManagedInstanceScanResultsScanResultCollection {
		return v.ScanResultCollections
	}).(GetWlmsManagedInstanceScanResultsScanResultCollectionArrayOutput)
}

// The name of the WebLogic server to which the server check belongs.
func (o GetWlmsManagedInstanceScanResultsResultOutput) ServerName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetWlmsManagedInstanceScanResultsResult) *string { return v.ServerName }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the WebLogic domain.
func (o GetWlmsManagedInstanceScanResultsResultOutput) WlsDomainId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetWlmsManagedInstanceScanResultsResult) *string { return v.WlsDomainId }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetWlmsManagedInstanceScanResultsResultOutput{})
}
