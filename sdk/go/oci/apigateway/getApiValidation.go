// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package apigateway

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Api Validation resource in Oracle Cloud Infrastructure API Gateway service.
//
// Gets the API validation results.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/apigateway"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := apigateway.GetApiValidation(ctx, &apigateway.GetApiValidationArgs{
//				ApiId: testApi.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupApiValidation(ctx *pulumi.Context, args *LookupApiValidationArgs, opts ...pulumi.InvokeOption) (*LookupApiValidationResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupApiValidationResult
	err := ctx.Invoke("oci:ApiGateway/getApiValidation:getApiValidation", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getApiValidation.
type LookupApiValidationArgs struct {
	// The ocid of the API.
	ApiId string `pulumi:"apiId"`
}

// A collection of values returned by getApiValidation.
type LookupApiValidationResult struct {
	ApiId string `pulumi:"apiId"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// API validation results.
	Validations []GetApiValidationValidation `pulumi:"validations"`
}

func LookupApiValidationOutput(ctx *pulumi.Context, args LookupApiValidationOutputArgs, opts ...pulumi.InvokeOption) LookupApiValidationResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupApiValidationResultOutput, error) {
			args := v.(LookupApiValidationArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ApiGateway/getApiValidation:getApiValidation", args, LookupApiValidationResultOutput{}, options).(LookupApiValidationResultOutput), nil
		}).(LookupApiValidationResultOutput)
}

// A collection of arguments for invoking getApiValidation.
type LookupApiValidationOutputArgs struct {
	// The ocid of the API.
	ApiId pulumi.StringInput `pulumi:"apiId"`
}

func (LookupApiValidationOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupApiValidationArgs)(nil)).Elem()
}

// A collection of values returned by getApiValidation.
type LookupApiValidationResultOutput struct{ *pulumi.OutputState }

func (LookupApiValidationResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupApiValidationResult)(nil)).Elem()
}

func (o LookupApiValidationResultOutput) ToLookupApiValidationResultOutput() LookupApiValidationResultOutput {
	return o
}

func (o LookupApiValidationResultOutput) ToLookupApiValidationResultOutputWithContext(ctx context.Context) LookupApiValidationResultOutput {
	return o
}

func (o LookupApiValidationResultOutput) ApiId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApiValidationResult) string { return v.ApiId }).(pulumi.StringOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o LookupApiValidationResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupApiValidationResult) string { return v.Id }).(pulumi.StringOutput)
}

// API validation results.
func (o LookupApiValidationResultOutput) Validations() GetApiValidationValidationArrayOutput {
	return o.ApplyT(func(v LookupApiValidationResult) []GetApiValidationValidation { return v.Validations }).(GetApiValidationValidationArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupApiValidationResultOutput{})
}
