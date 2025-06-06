// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package streaming

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Connect Harnesses in Oracle Cloud Infrastructure Streaming service.
//
// Lists the connectharness.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/streaming"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := streaming.GetConnectHarnesses(ctx, &streaming.GetConnectHarnessesArgs{
//				CompartmentId: compartmentId,
//				Id:            pulumi.StringRef(connectHarnessId),
//				Name:          pulumi.StringRef(connectHarnessName),
//				State:         pulumi.StringRef(connectHarnessState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetConnectHarnesses(ctx *pulumi.Context, args *GetConnectHarnessesArgs, opts ...pulumi.InvokeOption) (*GetConnectHarnessesResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetConnectHarnessesResult
	err := ctx.Invoke("oci:Streaming/getConnectHarnesses:getConnectHarnesses", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getConnectHarnesses.
type GetConnectHarnessesArgs struct {
	// The OCID of the compartment.
	CompartmentId string                      `pulumi:"compartmentId"`
	Filters       []GetConnectHarnessesFilter `pulumi:"filters"`
	// A filter to return only resources that match the given ID exactly.
	Id *string `pulumi:"id"`
	// A filter to return only resources that match the given name exactly.
	Name *string `pulumi:"name"`
	// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
	State *string `pulumi:"state"`
}

// A collection of values returned by getConnectHarnesses.
type GetConnectHarnessesResult struct {
	// The OCID of the compartment that contains the connect harness.
	CompartmentId string `pulumi:"compartmentId"`
	// The list of connect_harness.
	ConnectHarnesses []GetConnectHarnessesConnectHarness `pulumi:"connectHarnesses"`
	Filters          []GetConnectHarnessesFilter         `pulumi:"filters"`
	// The OCID of the connect harness.
	Id *string `pulumi:"id"`
	// The name of the connect harness. Avoid entering confidential information.  Example: `JDBCConnector`
	Name *string `pulumi:"name"`
	// The current state of the connect harness.
	State *string `pulumi:"state"`
}

func GetConnectHarnessesOutput(ctx *pulumi.Context, args GetConnectHarnessesOutputArgs, opts ...pulumi.InvokeOption) GetConnectHarnessesResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetConnectHarnessesResultOutput, error) {
			args := v.(GetConnectHarnessesArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Streaming/getConnectHarnesses:getConnectHarnesses", args, GetConnectHarnessesResultOutput{}, options).(GetConnectHarnessesResultOutput), nil
		}).(GetConnectHarnessesResultOutput)
}

// A collection of arguments for invoking getConnectHarnesses.
type GetConnectHarnessesOutputArgs struct {
	// The OCID of the compartment.
	CompartmentId pulumi.StringInput                  `pulumi:"compartmentId"`
	Filters       GetConnectHarnessesFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given ID exactly.
	Id pulumi.StringPtrInput `pulumi:"id"`
	// A filter to return only resources that match the given name exactly.
	Name pulumi.StringPtrInput `pulumi:"name"`
	// A filter to only return resources that match the given lifecycle state. The state value is case-insensitive.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetConnectHarnessesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetConnectHarnessesArgs)(nil)).Elem()
}

// A collection of values returned by getConnectHarnesses.
type GetConnectHarnessesResultOutput struct{ *pulumi.OutputState }

func (GetConnectHarnessesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetConnectHarnessesResult)(nil)).Elem()
}

func (o GetConnectHarnessesResultOutput) ToGetConnectHarnessesResultOutput() GetConnectHarnessesResultOutput {
	return o
}

func (o GetConnectHarnessesResultOutput) ToGetConnectHarnessesResultOutputWithContext(ctx context.Context) GetConnectHarnessesResultOutput {
	return o
}

// The OCID of the compartment that contains the connect harness.
func (o GetConnectHarnessesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetConnectHarnessesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The list of connect_harness.
func (o GetConnectHarnessesResultOutput) ConnectHarnesses() GetConnectHarnessesConnectHarnessArrayOutput {
	return o.ApplyT(func(v GetConnectHarnessesResult) []GetConnectHarnessesConnectHarness { return v.ConnectHarnesses }).(GetConnectHarnessesConnectHarnessArrayOutput)
}

func (o GetConnectHarnessesResultOutput) Filters() GetConnectHarnessesFilterArrayOutput {
	return o.ApplyT(func(v GetConnectHarnessesResult) []GetConnectHarnessesFilter { return v.Filters }).(GetConnectHarnessesFilterArrayOutput)
}

// The OCID of the connect harness.
func (o GetConnectHarnessesResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetConnectHarnessesResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

// The name of the connect harness. Avoid entering confidential information.  Example: `JDBCConnector`
func (o GetConnectHarnessesResultOutput) Name() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetConnectHarnessesResult) *string { return v.Name }).(pulumi.StringPtrOutput)
}

// The current state of the connect harness.
func (o GetConnectHarnessesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetConnectHarnessesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetConnectHarnessesResultOutput{})
}
