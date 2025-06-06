// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dns

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Tsig Keys in Oracle Cloud Infrastructure DNS service.
//
// Gets a list of all TSIG keys in the specified compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/dns"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := dns.GetTsigKeys(ctx, &dns.GetTsigKeysArgs{
//				CompartmentId: compartmentId,
//				Id:            pulumi.StringRef(tsigKeyId),
//				Name:          pulumi.StringRef(tsigKeyName),
//				State:         pulumi.StringRef(tsigKeyState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetTsigKeys(ctx *pulumi.Context, args *GetTsigKeysArgs, opts ...pulumi.InvokeOption) (*GetTsigKeysResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetTsigKeysResult
	err := ctx.Invoke("oci:Dns/getTsigKeys:getTsigKeys", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getTsigKeys.
type GetTsigKeysArgs struct {
	// The OCID of the compartment the resource belongs to.
	CompartmentId string              `pulumi:"compartmentId"`
	Filters       []GetTsigKeysFilter `pulumi:"filters"`
	// The OCID of a resource.
	Id *string `pulumi:"id"`
	// The name of a resource.
	Name *string `pulumi:"name"`
	// The state of a resource.
	State *string `pulumi:"state"`
}

// A collection of values returned by getTsigKeys.
type GetTsigKeysResult struct {
	// The OCID of the compartment containing the TSIG key.
	CompartmentId string              `pulumi:"compartmentId"`
	Filters       []GetTsigKeysFilter `pulumi:"filters"`
	// The OCID of the resource.
	Id *string `pulumi:"id"`
	// A globally unique domain name identifying the key for a given pair of hosts.
	Name *string `pulumi:"name"`
	// The current state of the resource.
	State *string `pulumi:"state"`
	// The list of tsig_keys.
	TsigKeys []GetTsigKeysTsigKey `pulumi:"tsigKeys"`
}

func GetTsigKeysOutput(ctx *pulumi.Context, args GetTsigKeysOutputArgs, opts ...pulumi.InvokeOption) GetTsigKeysResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetTsigKeysResultOutput, error) {
			args := v.(GetTsigKeysArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Dns/getTsigKeys:getTsigKeys", args, GetTsigKeysResultOutput{}, options).(GetTsigKeysResultOutput), nil
		}).(GetTsigKeysResultOutput)
}

// A collection of arguments for invoking getTsigKeys.
type GetTsigKeysOutputArgs struct {
	// The OCID of the compartment the resource belongs to.
	CompartmentId pulumi.StringInput          `pulumi:"compartmentId"`
	Filters       GetTsigKeysFilterArrayInput `pulumi:"filters"`
	// The OCID of a resource.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// The name of a resource.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// The state of a resource.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetTsigKeysOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetTsigKeysArgs)(nil)).Elem()
}

// A collection of values returned by getTsigKeys.
type GetTsigKeysResultOutput struct{ *pulumi.OutputState }

func (GetTsigKeysResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetTsigKeysResult)(nil)).Elem()
}

func (o GetTsigKeysResultOutput) ToGetTsigKeysResultOutput() GetTsigKeysResultOutput {
	return o
}

func (o GetTsigKeysResultOutput) ToGetTsigKeysResultOutputWithContext(ctx context.Context) GetTsigKeysResultOutput {
	return o
}

// The OCID of the compartment containing the TSIG key.
func (o GetTsigKeysResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetTsigKeysResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetTsigKeysResultOutput) Filters() GetTsigKeysFilterArrayOutput {
	return o.ApplyT(func(v GetTsigKeysResult) []GetTsigKeysFilter { return v.Filters }).(GetTsigKeysFilterArrayOutput)
}

// The OCID of the resource.
func (o GetTsigKeysResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetTsigKeysResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// A globally unique domain name identifying the key for a given pair of hosts.
func (o GetTsigKeysResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetTsigKeysResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The current state of the resource.
func (o GetTsigKeysResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetTsigKeysResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

// The list of tsig_keys.
func (o GetTsigKeysResultOutput) TsigKeys() GetTsigKeysTsigKeyArrayOutput {
	return o.ApplyT(func(v GetTsigKeysResult) []GetTsigKeysTsigKey { return v.TsigKeys }).(GetTsigKeysTsigKeyArrayOutput)
}

func init() {
	pulumi.RegisterOutputType(GetTsigKeysResultOutput{})
}
