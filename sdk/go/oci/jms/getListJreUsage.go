// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package jms

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific List Jre Usage resource in Oracle Cloud Infrastructure Jms service.
//
// List Java Runtime usage in a specified host filtered by query parameters.
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
//			_, err := jms.GetListJreUsage(ctx, &jms.GetListJreUsageArgs{
//				ApplicationId:   pulumi.StringRef(testApplication.Id),
//				ApplicationName: pulumi.StringRef(testApplication.Name),
//				CompartmentId:   pulumi.StringRef(compartmentId),
//				HostId:          pulumi.StringRef(testHost.Id),
//				TimeEnd:         pulumi.StringRef(listJreUsageTimeEnd),
//				TimeStart:       pulumi.StringRef(listJreUsageTimeStart),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetListJreUsage(ctx *pulumi.Context, args *GetListJreUsageArgs, opts ...pulumi.InvokeOption) (*GetListJreUsageResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetListJreUsageResult
	err := ctx.Invoke("oci:Jms/getListJreUsage:getListJreUsage", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getListJreUsage.
type GetListJreUsageArgs struct {
	// The Fleet-unique identifier of the application.
	ApplicationId *string `pulumi:"applicationId"`
	// The name of the application.
	ApplicationName *string `pulumi:"applicationName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
	CompartmentId *string `pulumi:"compartmentId"`
	// The host [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
	HostId *string `pulumi:"hostId"`
	// The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeEnd *string `pulumi:"timeEnd"`
	// The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeStart *string `pulumi:"timeStart"`
}

// A collection of values returned by getListJreUsage.
type GetListJreUsageResult struct {
	ApplicationId   *string `pulumi:"applicationId"`
	ApplicationName *string `pulumi:"applicationName"`
	CompartmentId   *string `pulumi:"compartmentId"`
	HostId          *string `pulumi:"hostId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// A list of Java Runtimes.
	Items []GetListJreUsageItem `pulumi:"items"`
	// Upper bound of the specified time period filter. JMS provides a view of the data that is _per day_. The query uses only the date element of the parameter.
	TimeEnd *string `pulumi:"timeEnd"`
	// Lower bound of the specified time period filter. JMS provides a view of the data that is _per day_. The query uses only the date element of the parameter.
	TimeStart *string `pulumi:"timeStart"`
}

func GetListJreUsageOutput(ctx *pulumi.Context, args GetListJreUsageOutputArgs, opts ...pulumi.InvokeOption) GetListJreUsageResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetListJreUsageResultOutput, error) {
			args := v.(GetListJreUsageArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Jms/getListJreUsage:getListJreUsage", args, GetListJreUsageResultOutput{}, options).(GetListJreUsageResultOutput), nil
		}).(GetListJreUsageResultOutput)
}

// A collection of arguments for invoking getListJreUsage.
type GetListJreUsageOutputArgs struct {
	// The Fleet-unique identifier of the application.
	ApplicationId pulumi.StringPtrInput `pulumi:"applicationId"`
	// The name of the application.
	ApplicationName pulumi.StringPtrInput `pulumi:"applicationName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which to list resources.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// The host [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the managed instance.
	HostId pulumi.StringPtrInput `pulumi:"hostId"`
	// The end of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeEnd pulumi.StringPtrInput `pulumi:"timeEnd"`
	// The start of the time period during which resources are searched (formatted according to [RFC3339](https://datatracker.ietf.org/doc/html/rfc3339)).
	TimeStart pulumi.StringPtrInput `pulumi:"timeStart"`
}

func (GetListJreUsageOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetListJreUsageArgs)(nil)).Elem()
}

// A collection of values returned by getListJreUsage.
type GetListJreUsageResultOutput struct{ *pulumi.OutputState }

func (GetListJreUsageResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetListJreUsageResult)(nil)).Elem()
}

func (o GetListJreUsageResultOutput) ToGetListJreUsageResultOutput() GetListJreUsageResultOutput {
	return o
}

func (o GetListJreUsageResultOutput) ToGetListJreUsageResultOutputWithContext(ctx context.Context) GetListJreUsageResultOutput {
	return o
}

func (o GetListJreUsageResultOutput) ApplicationId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetListJreUsageResult) *string { return v.ApplicationId }).(pulumi.StringPtrOutput)
}

func (o GetListJreUsageResultOutput) ApplicationName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetListJreUsageResult) *string { return v.ApplicationName }).(pulumi.StringPtrOutput)
}

func (o GetListJreUsageResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetListJreUsageResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

func (o GetListJreUsageResultOutput) HostId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetListJreUsageResult) *string { return v.HostId }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetListJreUsageResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetListJreUsageResult) string { return v.Id }).(pulumi.StringOutput)
}

// A list of Java Runtimes.
func (o GetListJreUsageResultOutput) Items() GetListJreUsageItemArrayOutput {
	return o.ApplyT(func(v GetListJreUsageResult) []GetListJreUsageItem { return v.Items }).(GetListJreUsageItemArrayOutput)
}

// Upper bound of the specified time period filter. JMS provides a view of the data that is _per day_. The query uses only the date element of the parameter.
func (o GetListJreUsageResultOutput) TimeEnd() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetListJreUsageResult) *string { return v.TimeEnd }).(pulumi.StringPtrOutput)
}

// Lower bound of the specified time period filter. JMS provides a view of the data that is _per day_. The query uses only the date element of the parameter.
func (o GetListJreUsageResultOutput) TimeStart() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetListJreUsageResult) *string { return v.TimeStart }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetListJreUsageResultOutput{})
}
