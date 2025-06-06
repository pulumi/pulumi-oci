// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package apigateway

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Gateways in Oracle Cloud Infrastructure API Gateway service.
//
// Returns a list of gateways.
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
//			_, err := apigateway.GetGateways(ctx, &apigateway.GetGatewaysArgs{
//				CompartmentId: compartmentId,
//				CertificateId: pulumi.StringRef(ociApigatewayCertificate.TestCertificate.Id),
//				DisplayName:   pulumi.StringRef(gatewayDisplayName),
//				State:         pulumi.StringRef(gatewayState),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetGateways(ctx *pulumi.Context, args *GetGatewaysArgs, opts ...pulumi.InvokeOption) (*GetGatewaysResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetGatewaysResult
	err := ctx.Invoke("oci:ApiGateway/getGateways:getGateways", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getGateways.
type GetGatewaysArgs struct {
	// Filter gateways by the certificate ocid.
	CertificateId *string `pulumi:"certificateId"`
	// The ocid of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
	DisplayName *string             `pulumi:"displayName"`
	Filters     []GetGatewaysFilter `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state.  Example: `SUCCEEDED`
	State *string `pulumi:"state"`
}

// A collection of values returned by getGateways.
type GetGatewaysResult struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
	CertificateId *string `pulumi:"certificateId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
	CompartmentId string `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
	DisplayName *string             `pulumi:"displayName"`
	Filters     []GetGatewaysFilter `pulumi:"filters"`
	// The list of gateway_collection.
	GatewayCollections []GetGatewaysGatewayCollection `pulumi:"gatewayCollections"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The current state of the gateway.
	State *string `pulumi:"state"`
}

func GetGatewaysOutput(ctx *pulumi.Context, args GetGatewaysOutputArgs, opts ...pulumi.InvokeOption) GetGatewaysResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetGatewaysResultOutput, error) {
			args := v.(GetGatewaysArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:ApiGateway/getGateways:getGateways", args, GetGatewaysResultOutput{}, options).(GetGatewaysResultOutput), nil
		}).(GetGatewaysResultOutput)
}

// A collection of arguments for invoking getGateways.
type GetGatewaysOutputArgs struct {
	// Filter gateways by the certificate ocid.
	CertificateId pulumi.StringPtrInput `pulumi:"certificateId"`
	// The ocid of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A user-friendly name. Does not have to be unique, and it's changeable.  Example: `My new resource`
	DisplayName pulumi.StringPtrInput       `pulumi:"displayName"`
	Filters     GetGatewaysFilterArrayInput `pulumi:"filters"`
	// A filter to return only resources that match the given lifecycle state.  Example: `SUCCEEDED`
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetGatewaysOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetGatewaysArgs)(nil)).Elem()
}

// A collection of values returned by getGateways.
type GetGatewaysResultOutput struct{ *pulumi.OutputState }

func (GetGatewaysResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetGatewaysResult)(nil)).Elem()
}

func (o GetGatewaysResultOutput) ToGetGatewaysResultOutput() GetGatewaysResultOutput {
	return o
}

func (o GetGatewaysResultOutput) ToGetGatewaysResultOutputWithContext(ctx context.Context) GetGatewaysResultOutput {
	return o
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
func (o GetGatewaysResultOutput) CertificateId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetGatewaysResult) *string { return v.CertificateId }).(pulumi.StringPtrOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
func (o GetGatewaysResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetGatewaysResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
func (o GetGatewaysResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetGatewaysResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetGatewaysResultOutput) Filters() GetGatewaysFilterArrayOutput {
	return o.ApplyT(func(v GetGatewaysResult) []GetGatewaysFilter { return v.Filters }).(GetGatewaysFilterArrayOutput)
}

// The list of gateway_collection.
func (o GetGatewaysResultOutput) GatewayCollections() GetGatewaysGatewayCollectionArrayOutput {
	return o.ApplyT(func(v GetGatewaysResult) []GetGatewaysGatewayCollection { return v.GatewayCollections }).(GetGatewaysGatewayCollectionArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetGatewaysResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetGatewaysResult) string { return v.Id }).(pulumi.StringOutput)
}

// The current state of the gateway.
func (o GetGatewaysResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetGatewaysResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetGatewaysResultOutput{})
}
