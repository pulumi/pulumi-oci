// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package apigateway

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Gateway resource in Oracle Cloud Infrastructure API Gateway service.
//
// Gets a gateway by identifier.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/ApiGateway"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := ApiGateway.GetGateway(ctx, &apigateway.GetGatewayArgs{
//				GatewayId: oci_apigateway_gateway.Test_gateway.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupGateway(ctx *pulumi.Context, args *LookupGatewayArgs, opts ...pulumi.InvokeOption) (*LookupGatewayResult, error) {
	var rv LookupGatewayResult
	err := ctx.Invoke("oci:ApiGateway/getGateway:getGateway", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getGateway.
type LookupGatewayArgs struct {
	// The ocid of the gateway.
	GatewayId string `pulumi:"gatewayId"`
}

// A collection of values returned by getGateway.
type LookupGatewayResult struct {
	// An array of CA bundles that should be used on the Gateway for TLS validation.
	CaBundles []GetGatewayCaBundle `pulumi:"caBundles"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
	CertificateId string `pulumi:"certificateId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
	DisplayName string `pulumi:"displayName"`
	// Gateway endpoint type. `PUBLIC` will have a public ip address assigned to it, while `PRIVATE` will only be accessible on a private IP address on the subnet.  Example: `PUBLIC` or `PRIVATE`
	EndpointType string `pulumi:"endpointType"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	GatewayId    string                 `pulumi:"gatewayId"`
	// The hostname for APIs deployed on the gateway.
	Hostname string `pulumi:"hostname"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
	Id string `pulumi:"id"`
	// An array of IP addresses associated with the gateway.
	IpAddresses []GetGatewayIpAddress `pulumi:"ipAddresses"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails string `pulumi:"lifecycleDetails"`
	// An array of Network Security Groups OCIDs associated with this API Gateway.
	NetworkSecurityGroupIds []string `pulumi:"networkSecurityGroupIds"`
	// Base Gateway response cache.
	ResponseCacheDetails []GetGatewayResponseCacheDetail `pulumi:"responseCacheDetails"`
	// The current state of the gateway.
	State string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which related resources are created.
	SubnetId string `pulumi:"subnetId"`
	// The time this resource was created. An RFC3339 formatted datetime string.
	TimeCreated string `pulumi:"timeCreated"`
	// The time this resource was last updated. An RFC3339 formatted datetime string.
	TimeUpdated string `pulumi:"timeUpdated"`
}

func LookupGatewayOutput(ctx *pulumi.Context, args LookupGatewayOutputArgs, opts ...pulumi.InvokeOption) LookupGatewayResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupGatewayResult, error) {
			args := v.(LookupGatewayArgs)
			r, err := LookupGateway(ctx, &args, opts...)
			var s LookupGatewayResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupGatewayResultOutput)
}

// A collection of arguments for invoking getGateway.
type LookupGatewayOutputArgs struct {
	// The ocid of the gateway.
	GatewayId pulumi.StringInput `pulumi:"gatewayId"`
}

func (LookupGatewayOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupGatewayArgs)(nil)).Elem()
}

// A collection of values returned by getGateway.
type LookupGatewayResultOutput struct{ *pulumi.OutputState }

func (LookupGatewayResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupGatewayResult)(nil)).Elem()
}

func (o LookupGatewayResultOutput) ToLookupGatewayResultOutput() LookupGatewayResultOutput {
	return o
}

func (o LookupGatewayResultOutput) ToLookupGatewayResultOutputWithContext(ctx context.Context) LookupGatewayResultOutput {
	return o
}

// An array of CA bundles that should be used on the Gateway for TLS validation.
func (o LookupGatewayResultOutput) CaBundles() GetGatewayCaBundleArrayOutput {
	return o.ApplyT(func(v LookupGatewayResult) []GetGatewayCaBundle { return v.CaBundles }).(GetGatewayCaBundleArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
func (o LookupGatewayResultOutput) CertificateId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupGatewayResult) string { return v.CertificateId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
func (o LookupGatewayResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupGatewayResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o LookupGatewayResultOutput) DefinedTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupGatewayResult) map[string]interface{} { return v.DefinedTags }).(pulumi.MapOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
func (o LookupGatewayResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupGatewayResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Gateway endpoint type. `PUBLIC` will have a public ip address assigned to it, while `PRIVATE` will only be accessible on a private IP address on the subnet.  Example: `PUBLIC` or `PRIVATE`
func (o LookupGatewayResultOutput) EndpointType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupGatewayResult) string { return v.EndpointType }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupGatewayResultOutput) FreeformTags() pulumi.MapOutput {
	return o.ApplyT(func(v LookupGatewayResult) map[string]interface{} { return v.FreeformTags }).(pulumi.MapOutput)
}

func (o LookupGatewayResultOutput) GatewayId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupGatewayResult) string { return v.GatewayId }).(pulumi.StringOutput)
}

// The hostname for APIs deployed on the gateway.
func (o LookupGatewayResultOutput) Hostname() pulumi.StringOutput {
	return o.ApplyT(func(v LookupGatewayResult) string { return v.Hostname }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
func (o LookupGatewayResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupGatewayResult) string { return v.Id }).(pulumi.StringOutput)
}

// An array of IP addresses associated with the gateway.
func (o LookupGatewayResultOutput) IpAddresses() GetGatewayIpAddressArrayOutput {
	return o.ApplyT(func(v LookupGatewayResult) []GetGatewayIpAddress { return v.IpAddresses }).(GetGatewayIpAddressArrayOutput)
}

// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
func (o LookupGatewayResultOutput) LifecycleDetails() pulumi.StringOutput {
	return o.ApplyT(func(v LookupGatewayResult) string { return v.LifecycleDetails }).(pulumi.StringOutput)
}

// An array of Network Security Groups OCIDs associated with this API Gateway.
func (o LookupGatewayResultOutput) NetworkSecurityGroupIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupGatewayResult) []string { return v.NetworkSecurityGroupIds }).(pulumi.StringArrayOutput)
}

// Base Gateway response cache.
func (o LookupGatewayResultOutput) ResponseCacheDetails() GetGatewayResponseCacheDetailArrayOutput {
	return o.ApplyT(func(v LookupGatewayResult) []GetGatewayResponseCacheDetail { return v.ResponseCacheDetails }).(GetGatewayResponseCacheDetailArrayOutput)
}

// The current state of the gateway.
func (o LookupGatewayResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupGatewayResult) string { return v.State }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which related resources are created.
func (o LookupGatewayResultOutput) SubnetId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupGatewayResult) string { return v.SubnetId }).(pulumi.StringOutput)
}

// The time this resource was created. An RFC3339 formatted datetime string.
func (o LookupGatewayResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupGatewayResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time this resource was last updated. An RFC3339 formatted datetime string.
func (o LookupGatewayResultOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupGatewayResult) string { return v.TimeUpdated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupGatewayResultOutput{})
}