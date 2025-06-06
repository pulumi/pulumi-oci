// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package jms

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Fleet Performance Tuning Analysis Results in Oracle Cloud Infrastructure Jms service.
//
// List Performance Tuning Analysis results.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/jms"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := jms.GetFleetPerformanceTuningAnalysisResults(ctx, &jms.GetFleetPerformanceTuningAnalysisResultsArgs{
//				FleetId:           testFleet.Id,
//				ApplicationId:     pulumi.StringRef(fleetPerformanceTuningAnalysisResultApplicationId),
//				ApplicationName:   pulumi.StringRef(fleetPerformanceTuningAnalysisResultApplicationName),
//				HostName:          pulumi.StringRef(fleetPerformanceTuningAnalysisResultHostName),
//				ManagedInstanceId: pulumi.StringRef(fleetPerformanceTuningAnalysisResultManagedInstanceId),
//				TimeEnd:           pulumi.StringRef(fleetPerformanceTuningAnalysisResultTimeEnd),
//				TimeStart:         pulumi.StringRef(fleetPerformanceTuningAnalysisResultTimeStart),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetFleetPerformanceTuningAnalysisResults(ctx *pulumi.Context, args *GetFleetPerformanceTuningAnalysisResultsArgs, opts ...pulumi.InvokeOption) (*GetFleetPerformanceTuningAnalysisResultsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetFleetPerformanceTuningAnalysisResultsResult
	err := ctx.Invoke("oci:Jms/getFleetPerformanceTuningAnalysisResults:getFleetPerformanceTuningAnalysisResults", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getFleetPerformanceTuningAnalysisResults.
type GetFleetPerformanceTuningAnalysisResultsArgs struct {
	// The Fleet-unique identifier of the related application.
	ApplicationId *string `pulumi:"applicationId"`
	// The name of the application.
	ApplicationName *string                                          `pulumi:"applicationName"`
	Filters         []GetFleetPerformanceTuningAnalysisResultsFilter `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
	FleetId string `pulumi:"fleetId"`
	// The host [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
	HostName *string `pulumi:"hostName"`
	// The Fleet-unique identifier of the related managed instance.
	ManagedInstanceId *string `pulumi:"managedInstanceId"`
	// The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeEnd *string `pulumi:"timeEnd"`
	// The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeStart *string `pulumi:"timeStart"`
}

// A collection of values returned by getFleetPerformanceTuningAnalysisResults.
type GetFleetPerformanceTuningAnalysisResultsResult struct {
	// The OCID of the application for which the report has been generated.
	ApplicationId *string `pulumi:"applicationId"`
	// The name of the application for which the report has been generated.
	ApplicationName *string                                          `pulumi:"applicationName"`
	Filters         []GetFleetPerformanceTuningAnalysisResultsFilter `pulumi:"filters"`
	// The fleet OCID.
	FleetId string `pulumi:"fleetId"`
	// The hostname of the managed instance.
	HostName *string `pulumi:"hostName"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The managed instance OCID.
	ManagedInstanceId *string `pulumi:"managedInstanceId"`
	// The list of performance_tuning_analysis_result_collection.
	PerformanceTuningAnalysisResultCollections []GetFleetPerformanceTuningAnalysisResultsPerformanceTuningAnalysisResultCollection `pulumi:"performanceTuningAnalysisResultCollections"`
	TimeEnd                                    *string                                                                             `pulumi:"timeEnd"`
	TimeStart                                  *string                                                                             `pulumi:"timeStart"`
}

func GetFleetPerformanceTuningAnalysisResultsOutput(ctx *pulumi.Context, args GetFleetPerformanceTuningAnalysisResultsOutputArgs, opts ...pulumi.InvokeOption) GetFleetPerformanceTuningAnalysisResultsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetFleetPerformanceTuningAnalysisResultsResultOutput, error) {
			args := v.(GetFleetPerformanceTuningAnalysisResultsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Jms/getFleetPerformanceTuningAnalysisResults:getFleetPerformanceTuningAnalysisResults", args, GetFleetPerformanceTuningAnalysisResultsResultOutput{}, options).(GetFleetPerformanceTuningAnalysisResultsResultOutput), nil
		}).(GetFleetPerformanceTuningAnalysisResultsResultOutput)
}

// A collection of arguments for invoking getFleetPerformanceTuningAnalysisResults.
type GetFleetPerformanceTuningAnalysisResultsOutputArgs struct {
	// The Fleet-unique identifier of the related application.
	ApplicationId pulumi.StringPtrInput `pulumi:"applicationId"`
	// The name of the application.
	ApplicationName pulumi.StringPtrInput                                    `pulumi:"applicationName"`
	Filters         GetFleetPerformanceTuningAnalysisResultsFilterArrayInput `pulumi:"filters"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Fleet.
	FleetId pulumi.StringInput `pulumi:"fleetId"`
	// The host [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
	HostName pulumi.StringPtrInput `pulumi:"hostName"`
	// The Fleet-unique identifier of the related managed instance.
	ManagedInstanceId pulumi.StringPtrInput `pulumi:"managedInstanceId"`
	// The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeEnd pulumi.StringPtrInput `pulumi:"timeEnd"`
	// The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeStart pulumi.StringPtrInput `pulumi:"timeStart"`
}

func (GetFleetPerformanceTuningAnalysisResultsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFleetPerformanceTuningAnalysisResultsArgs)(nil)).Elem()
}

// A collection of values returned by getFleetPerformanceTuningAnalysisResults.
type GetFleetPerformanceTuningAnalysisResultsResultOutput struct{ *pulumi.OutputState }

func (GetFleetPerformanceTuningAnalysisResultsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetFleetPerformanceTuningAnalysisResultsResult)(nil)).Elem()
}

func (o GetFleetPerformanceTuningAnalysisResultsResultOutput) ToGetFleetPerformanceTuningAnalysisResultsResultOutput() GetFleetPerformanceTuningAnalysisResultsResultOutput {
	return o
}

func (o GetFleetPerformanceTuningAnalysisResultsResultOutput) ToGetFleetPerformanceTuningAnalysisResultsResultOutputWithContext(ctx context.Context) GetFleetPerformanceTuningAnalysisResultsResultOutput {
	return o
}

// The OCID of the application for which the report has been generated.
func (o GetFleetPerformanceTuningAnalysisResultsResultOutput) ApplicationId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFleetPerformanceTuningAnalysisResultsResult) *string { return v.ApplicationId }).(pulumi.StringPtrOutput)
}

// The name of the application for which the report has been generated.
func (o GetFleetPerformanceTuningAnalysisResultsResultOutput) ApplicationName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFleetPerformanceTuningAnalysisResultsResult) *string { return v.ApplicationName }).(pulumi.StringPtrOutput)
}

func (o GetFleetPerformanceTuningAnalysisResultsResultOutput) Filters() GetFleetPerformanceTuningAnalysisResultsFilterArrayOutput {
	return o.ApplyT(func(v GetFleetPerformanceTuningAnalysisResultsResult) []GetFleetPerformanceTuningAnalysisResultsFilter {
		return v.Filters
	}).(GetFleetPerformanceTuningAnalysisResultsFilterArrayOutput)
}

// The fleet OCID.
func (o GetFleetPerformanceTuningAnalysisResultsResultOutput) FleetId() pulumi.StringOutput {
	return o.ApplyT(func(v GetFleetPerformanceTuningAnalysisResultsResult) string { return v.FleetId }).(pulumi.StringOutput)
}

// The hostname of the managed instance.
func (o GetFleetPerformanceTuningAnalysisResultsResultOutput) HostName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFleetPerformanceTuningAnalysisResultsResult) *string { return v.HostName }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetFleetPerformanceTuningAnalysisResultsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetFleetPerformanceTuningAnalysisResultsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The managed instance OCID.
func (o GetFleetPerformanceTuningAnalysisResultsResultOutput) ManagedInstanceId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFleetPerformanceTuningAnalysisResultsResult) *string { return v.ManagedInstanceId }).(pulumi.StringPtrOutput)
}

// The list of performance_tuning_analysis_result_collection.
func (o GetFleetPerformanceTuningAnalysisResultsResultOutput) PerformanceTuningAnalysisResultCollections() GetFleetPerformanceTuningAnalysisResultsPerformanceTuningAnalysisResultCollectionArrayOutput {
	return o.ApplyT(func(v GetFleetPerformanceTuningAnalysisResultsResult) []GetFleetPerformanceTuningAnalysisResultsPerformanceTuningAnalysisResultCollection {
		return v.PerformanceTuningAnalysisResultCollections
	}).(GetFleetPerformanceTuningAnalysisResultsPerformanceTuningAnalysisResultCollectionArrayOutput)
}

func (o GetFleetPerformanceTuningAnalysisResultsResultOutput) TimeEnd() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFleetPerformanceTuningAnalysisResultsResult) *string { return v.TimeEnd }).(pulumi.StringPtrOutput)
}

func (o GetFleetPerformanceTuningAnalysisResultsResultOutput) TimeStart() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetFleetPerformanceTuningAnalysisResultsResult) *string { return v.TimeStart }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetFleetPerformanceTuningAnalysisResultsResultOutput{})
}
