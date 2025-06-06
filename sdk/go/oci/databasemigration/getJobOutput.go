// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package databasemigration

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Job Output resource in Oracle Cloud Infrastructure Database Migration service.
//
// # List the Job Outputs
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/databasemigration"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := databasemigration.GetJobOutput(ctx, databasemigration.GetJobOutputArgs{
//				JobId: testJob.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetJobOutput(ctx *pulumi.Context, args *GetJobOutputArgs, opts ...pulumi.InvokeOption) (*GetJobOutputResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetJobOutputResult
	err := ctx.Invoke("oci:DatabaseMigration/getJobOutput:getJobOutput", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getJobOutput.
type GetJobOutputArgs struct {
	// The OCID of the job
	JobId string `pulumi:"jobId"`
}

// A collection of values returned by getJobOutput.
type GetJobOutputResult struct {
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// Items in collection.
	Items []GetJobOutputItem `pulumi:"items"`
	JobId string             `pulumi:"jobId"`
}

func GetJobOutputOutput(ctx *pulumi.Context, args GetJobOutputOutputArgs, opts ...pulumi.InvokeOption) GetJobOutputResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetJobOutputResultOutput, error) {
			args := v.(GetJobOutputArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DatabaseMigration/getJobOutput:getJobOutput", args, GetJobOutputResultOutput{}, options).(GetJobOutputResultOutput), nil
		}).(GetJobOutputResultOutput)
}

// A collection of arguments for invoking getJobOutput.
type GetJobOutputOutputArgs struct {
	// The OCID of the job
	JobId pulumi.StringInput `pulumi:"jobId"`
}

func (GetJobOutputOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetJobOutputArgs)(nil)).Elem()
}

// A collection of values returned by getJobOutput.
type GetJobOutputResultOutput struct{ *pulumi.OutputState }

func (GetJobOutputResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetJobOutputResult)(nil)).Elem()
}

func (o GetJobOutputResultOutput) ToGetJobOutputResultOutput() GetJobOutputResultOutput {
	return o
}

func (o GetJobOutputResultOutput) ToGetJobOutputResultOutputWithContext(ctx context.Context) GetJobOutputResultOutput {
	return o
}

// The provider-assigned unique ID for this managed resource.
func (o GetJobOutputResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetJobOutputResult) string { return v.Id }).(pulumi.StringOutput)
}

// Items in collection.
func (o GetJobOutputResultOutput) Items() GetJobOutputItemArrayOutput {
	return o.ApplyT(func(v GetJobOutputResult) []GetJobOutputItem { return v.Items }).(GetJobOutputItemArrayOutput)
}

func (o GetJobOutputResultOutput) JobId() pulumi.StringOutput {
	return o.ApplyT(func(v GetJobOutputResult) string { return v.JobId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetJobOutputResultOutput{})
}
