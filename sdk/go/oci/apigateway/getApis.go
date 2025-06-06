// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package apigateway

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Apis in Oracle Cloud Infrastructure API Gateway service.
//
// Returns a list of APIs.
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
//			_, err := apigateway.GetApis(ctx, &apigateway.GetApisArgs{
//				CompartmentId: compartmentId,
//				DisplayName:   pulumi.StringRef(apiDisplayName),
//				State:         pulumi.StringRef(apiState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetApis(ctx *pulumi.Context, args *GetApisArgs, opts ...pulumi.InvokeOption) (*GetApisResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetApisResult
	err := ctx.Invoke("oci:ApiGateway/getApis:getApis", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getApis.
type GetApisArgs struct {
	// The ocid of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
	DisplayName *string         `pulumi:"displayName"`
	Filters     []GetApisFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state.  Example: `ACTIVE`
	State *string `pulumi:"state"`
}

// A collection of values returned by getApis.
type GetApisResult struct {
	// The list of api_collection.
	ApiCollections []GetApisApiCollection `pulumi:"apiCollections"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
	DisplayName *string         `pulumi:"displayName"`
	Filters     []GetApisFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the API.
	State *string `pulumi:"state"`
}

func GetApisOutput(ctx *pulumi.Context, args GetApisOutputArgs, opts ...pulumi.InvokeOption) GetApisResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetApisResultOutput, error) {
			args := v.(GetApisArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ApiGateway/getApis:getApis", args, GetApisResultOutput{}, options).(GetApisResultOutput), nil
		}).(GetApisResultOutput)
}

// A collection of arguments for invoking getApis.
type GetApisOutputArgs struct {
	// The ocid of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
	DisplayName pulumi.StringPtrInput   `pulumi:"displayName"`
	Filters     GetApisFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state.  Example: `ACTIVE`
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetApisOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetApisArgs)(nil)).Elem()
}

// A collection of values returned by getApis.
type GetApisResultOutput struct{ *pulumi.OutputState }

func (GetApisResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetApisResult)(nil)).Elem()
}

func (o GetApisResultOutput) ToGetApisResultOutput() GetApisResultOutput {
	return o
}

func (o GetApisResultOutput) ToGetApisResultOutputWithContext(ctx context.Context) GetApisResultOutput {
	return o
}

// The list of api_collection.
func (o GetApisResultOutput) ApiCollections() GetApisApiCollectionArrayOutput {
	return o.ApplyT(func(v GetApisResult) []GetApisApiCollection { return v.ApiCollections }).(GetApisApiCollectionArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
func (o GetApisResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetApisResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
func (o GetApisResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetApisResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetApisResultOutput) Filters() GetApisFilterArrayOutput {
	return o.ApplyT(func(v GetApisResult) []GetApisFilter { return v.Filters }).(GetApisFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetApisResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetApisResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the API.
func (o GetApisResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetApisResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetApisResultOutput{})
}
