// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package identity

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Api Keys in Oracle Cloud Infrastructure Identity service.
//
// Lists the API signing keys for the specified user. A user can have a maximum of three keys.
//
// Every user has permission to use this API call for *their own user ID*.  An administrator in your
// organization does not need to write a policy to give users this ability.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Identity"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Identity.GetApiKeys(ctx, &identity.GetApiKeysArgs{
//				UserId: oci_identity_user.Test_user.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetApiKeys(ctx *pulumi.Context, args *GetApiKeysArgs, opts ...pulumi.InvokeOption) (*GetApiKeysResult, error) {
	var rv GetApiKeysResult
	err := ctx.Invoke("oci:Identity/getApiKeys:getApiKeys", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getApiKeys.
type GetApiKeysArgs struct {
	Filters []GetApiKeysFilter `pulumi:"filters"`
	// The OCID of the user.
	UserId string `pulumi:"userId"`
}

// A collection of values returned by getApiKeys.
type GetApiKeysResult struct {
	// The list of api_keys.
	ApiKeys []GetApiKeysApiKey `pulumi:"apiKeys"`
	Filters []GetApiKeysFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The OCID of the user the key belongs to.
	UserId string `pulumi:"userId"`
}

func GetApiKeysOutput(ctx *pulumi.Context, args GetApiKeysOutputArgs, opts ...pulumi.InvokeOption) GetApiKeysResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetApiKeysResult, error) {
			args := v.(GetApiKeysArgs)
			r, err := GetApiKeys(ctx, &args, opts...)
			var s GetApiKeysResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetApiKeysResultOutput)
}

// A collection of arguments for invoking getApiKeys.
type GetApiKeysOutputArgs struct {
	Filters GetApiKeysFilterArrayInput `pulumi:"filters"`
	// The OCID of the user.
	UserId pulumi.StringInput `pulumi:"userId"`
}

func (GetApiKeysOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetApiKeysArgs)(nil)).Elem()
}

// A collection of values returned by getApiKeys.
type GetApiKeysResultOutput struct{ *pulumi.OutputState }

func (GetApiKeysResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetApiKeysResult)(nil)).Elem()
}

func (o GetApiKeysResultOutput) ToGetApiKeysResultOutput() GetApiKeysResultOutput {
	return o
}

func (o GetApiKeysResultOutput) ToGetApiKeysResultOutputWithContext(ctx context.Context) GetApiKeysResultOutput {
	return o
}

// The list of api_keys.
func (o GetApiKeysResultOutput) ApiKeys() GetApiKeysApiKeyArrayOutput {
	return o.ApplyT(func(v GetApiKeysResult) []GetApiKeysApiKey { return v.ApiKeys }).(GetApiKeysApiKeyArrayOutput)
}

func (o GetApiKeysResultOutput) Filters() GetApiKeysFilterArrayOutput {
	return o.ApplyT(func(v GetApiKeysResult) []GetApiKeysFilter { return v.Filters }).(GetApiKeysFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetApiKeysResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetApiKeysResult) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the user the key belongs to.
func (o GetApiKeysResultOutput) UserId() pulumi.StringOutput {
	return o.ApplyT(func(v GetApiKeysResult) string { return v.UserId }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(GetApiKeysResultOutput{})
}