// *** WARNING: this file was generated by the Pulumi Terraform Bridge (tfgen) Tool. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package apigateway

import (
	"context"
	"reflect"

	"github.com/pkg/errors"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Gateway resource in Oracle Cloud Infrastructure API Gateway service.
//
// Creates a new gateway.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
// 	"github.com/pulumi/pulumi-oci/sdk/go/oci/ApiGateway"
// 	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
// )
//
// func main() {
// 	pulumi.Run(func(ctx *pulumi.Context) error {
// 		_, err := ApiGateway.NewGateway(ctx, "testGateway", &ApiGateway.GatewayArgs{
// 			CompartmentId: pulumi.Any(_var.Compartment_id),
// 			EndpointType:  pulumi.Any(_var.Gateway_endpoint_type),
// 			SubnetId:      pulumi.Any(oci_core_subnet.Test_subnet.Id),
// 			CertificateId: pulumi.Any(oci_apigateway_certificate.Test_certificate.Id),
// 			CaBundles: apigateway.GatewayCaBundleArray{
// 				&apigateway.GatewayCaBundleArgs{
// 					Type:                   pulumi.Any(_var.Gateway_ca_bundles_type),
// 					CaBundleId:             pulumi.Any(oci_apigateway_ca_bundle.Test_ca_bundle.Id),
// 					CertificateAuthorityId: pulumi.Any(oci_apigateway_certificate_authority.Test_certificate_authority.Id),
// 				},
// 			},
// 			DefinedTags: pulumi.AnyMap{
// 				"Operations.CostCenter": pulumi.Any("42"),
// 			},
// 			DisplayName: pulumi.Any(_var.Gateway_display_name),
// 			FreeformTags: pulumi.AnyMap{
// 				"Department": pulumi.Any("Finance"),
// 			},
// 			NetworkSecurityGroupIds: pulumi.Any(_var.Gateway_network_security_group_ids),
// 			ResponseCacheDetails: &apigateway.GatewayResponseCacheDetailsArgs{
// 				Type:                              pulumi.Any(_var.Gateway_response_cache_details_type),
// 				AuthenticationSecretId:            pulumi.Any(oci_vault_secret.Test_secret.Id),
// 				AuthenticationSecretVersionNumber: pulumi.Any(_var.Gateway_response_cache_details_authentication_secret_version_number),
// 				ConnectTimeoutInMs:                pulumi.Any(_var.Gateway_response_cache_details_connect_timeout_in_ms),
// 				IsSslEnabled:                      pulumi.Any(_var.Gateway_response_cache_details_is_ssl_enabled),
// 				IsSslVerifyDisabled:               pulumi.Any(_var.Gateway_response_cache_details_is_ssl_verify_disabled),
// 				ReadTimeoutInMs:                   pulumi.Any(_var.Gateway_response_cache_details_read_timeout_in_ms),
// 				SendTimeoutInMs:                   pulumi.Any(_var.Gateway_response_cache_details_send_timeout_in_ms),
// 				Servers: apigateway.GatewayResponseCacheDetailsServerArray{
// 					&apigateway.GatewayResponseCacheDetailsServerArgs{
// 						Host: pulumi.Any(_var.Gateway_response_cache_details_servers_host),
// 						Port: pulumi.Any(_var.Gateway_response_cache_details_servers_port),
// 					},
// 				},
// 			},
// 		})
// 		if err != nil {
// 			return err
// 		}
// 		return nil
// 	})
// }
// ```
//
// ## Import
//
// Gateways can be imported using the `id`, e.g.
//
// ```sh
//  $ pulumi import oci:ApiGateway/gateway:Gateway test_gateway "id"
// ```
type Gateway struct {
	pulumi.CustomResourceState

	// (Updatable) An array of CA bundles that should be used on the Gateway for TLS validation.
	CaBundles GatewayCaBundleArrayOutput `pulumi:"caBundles"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
	CertificateId pulumi.StringOutput `pulumi:"certificateId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapOutput `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// Gateway endpoint type. `PUBLIC` will have a public ip address assigned to it, while `PRIVATE` will only be accessible on a private IP address on the subnet.  Example: `PUBLIC` or `PRIVATE`
	EndpointType pulumi.StringOutput `pulumi:"endpointType"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapOutput `pulumi:"freeformTags"`
	// The hostname for APIs deployed on the gateway.
	Hostname pulumi.StringOutput `pulumi:"hostname"`
	// An array of IP addresses associated with the gateway.
	IpAddresses GatewayIpAddressArrayOutput `pulumi:"ipAddresses"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails pulumi.StringOutput `pulumi:"lifecycleDetails"`
	// (Updatable) An array of Network Security Groups OCIDs associated with this API Gateway.
	NetworkSecurityGroupIds pulumi.StringArrayOutput `pulumi:"networkSecurityGroupIds"`
	// (Updatable) Base Gateway response cache.
	ResponseCacheDetails GatewayResponseCacheDetailsOutput `pulumi:"responseCacheDetails"`
	// The current state of the gateway.
	State pulumi.StringOutput `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which related resources are created.
	SubnetId pulumi.StringOutput `pulumi:"subnetId"`
	// The time this resource was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time this resource was last updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewGateway registers a new resource with the given unique name, arguments, and options.
func NewGateway(ctx *pulumi.Context,
	name string, args *GatewayArgs, opts ...pulumi.ResourceOption) (*Gateway, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.EndpointType == nil {
		return nil, errors.New("invalid value for required argument 'EndpointType'")
	}
	if args.SubnetId == nil {
		return nil, errors.New("invalid value for required argument 'SubnetId'")
	}
	var resource Gateway
	err := ctx.RegisterResource("oci:ApiGateway/gateway:Gateway", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetGateway gets an existing Gateway resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetGateway(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *GatewayState, opts ...pulumi.ResourceOption) (*Gateway, error) {
	var resource Gateway
	err := ctx.ReadResource("oci:ApiGateway/gateway:Gateway", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Gateway resources.
type gatewayState struct {
	// (Updatable) An array of CA bundles that should be used on the Gateway for TLS validation.
	CaBundles []GatewayCaBundle `pulumi:"caBundles"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
	CertificateId *string `pulumi:"certificateId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
	DisplayName *string `pulumi:"displayName"`
	// Gateway endpoint type. `PUBLIC` will have a public ip address assigned to it, while `PRIVATE` will only be accessible on a private IP address on the subnet.  Example: `PUBLIC` or `PRIVATE`
	EndpointType *string `pulumi:"endpointType"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// The hostname for APIs deployed on the gateway.
	Hostname *string `pulumi:"hostname"`
	// An array of IP addresses associated with the gateway.
	IpAddresses []GatewayIpAddress `pulumi:"ipAddresses"`
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails *string `pulumi:"lifecycleDetails"`
	// (Updatable) An array of Network Security Groups OCIDs associated with this API Gateway.
	NetworkSecurityGroupIds []string `pulumi:"networkSecurityGroupIds"`
	// (Updatable) Base Gateway response cache.
	ResponseCacheDetails *GatewayResponseCacheDetails `pulumi:"responseCacheDetails"`
	// The current state of the gateway.
	State *string `pulumi:"state"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which related resources are created.
	SubnetId *string `pulumi:"subnetId"`
	// The time this resource was created. An RFC3339 formatted datetime string.
	TimeCreated *string `pulumi:"timeCreated"`
	// The time this resource was last updated. An RFC3339 formatted datetime string.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type GatewayState struct {
	// (Updatable) An array of CA bundles that should be used on the Gateway for TLS validation.
	CaBundles GatewayCaBundleArrayInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
	CertificateId pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
	DisplayName pulumi.StringPtrInput
	// Gateway endpoint type. `PUBLIC` will have a public ip address assigned to it, while `PRIVATE` will only be accessible on a private IP address on the subnet.  Example: `PUBLIC` or `PRIVATE`
	EndpointType pulumi.StringPtrInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// The hostname for APIs deployed on the gateway.
	Hostname pulumi.StringPtrInput
	// An array of IP addresses associated with the gateway.
	IpAddresses GatewayIpAddressArrayInput
	// A message describing the current state in more detail. For example, can be used to provide actionable information for a resource in a Failed state.
	LifecycleDetails pulumi.StringPtrInput
	// (Updatable) An array of Network Security Groups OCIDs associated with this API Gateway.
	NetworkSecurityGroupIds pulumi.StringArrayInput
	// (Updatable) Base Gateway response cache.
	ResponseCacheDetails GatewayResponseCacheDetailsPtrInput
	// The current state of the gateway.
	State pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which related resources are created.
	SubnetId pulumi.StringPtrInput
	// The time this resource was created. An RFC3339 formatted datetime string.
	TimeCreated pulumi.StringPtrInput
	// The time this resource was last updated. An RFC3339 formatted datetime string.
	TimeUpdated pulumi.StringPtrInput
}

func (GatewayState) ElementType() reflect.Type {
	return reflect.TypeOf((*gatewayState)(nil)).Elem()
}

type gatewayArgs struct {
	// (Updatable) An array of CA bundles that should be used on the Gateway for TLS validation.
	CaBundles []GatewayCaBundle `pulumi:"caBundles"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
	CertificateId *string `pulumi:"certificateId"`
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]interface{} `pulumi:"definedTags"`
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
	DisplayName *string `pulumi:"displayName"`
	// Gateway endpoint type. `PUBLIC` will have a public ip address assigned to it, while `PRIVATE` will only be accessible on a private IP address on the subnet.  Example: `PUBLIC` or `PRIVATE`
	EndpointType string `pulumi:"endpointType"`
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]interface{} `pulumi:"freeformTags"`
	// (Updatable) An array of Network Security Groups OCIDs associated with this API Gateway.
	NetworkSecurityGroupIds []string `pulumi:"networkSecurityGroupIds"`
	// (Updatable) Base Gateway response cache.
	ResponseCacheDetails *GatewayResponseCacheDetails `pulumi:"responseCacheDetails"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which related resources are created.
	SubnetId string `pulumi:"subnetId"`
}

// The set of arguments for constructing a Gateway resource.
type GatewayArgs struct {
	// (Updatable) An array of CA bundles that should be used on the Gateway for TLS validation.
	CaBundles GatewayCaBundleArrayInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the resource.
	CertificateId pulumi.StringPtrInput
	// (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment in which the resource is created.
	CompartmentId pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags pulumi.MapInput
	// (Updatable) A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.  Example: `My new resource`
	DisplayName pulumi.StringPtrInput
	// Gateway endpoint type. `PUBLIC` will have a public ip address assigned to it, while `PRIVATE` will only be accessible on a private IP address on the subnet.  Example: `PUBLIC` or `PRIVATE`
	EndpointType pulumi.StringInput
	// (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags pulumi.MapInput
	// (Updatable) An array of Network Security Groups OCIDs associated with this API Gateway.
	NetworkSecurityGroupIds pulumi.StringArrayInput
	// (Updatable) Base Gateway response cache.
	ResponseCacheDetails GatewayResponseCacheDetailsPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the subnet in which related resources are created.
	SubnetId pulumi.StringInput
}

func (GatewayArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*gatewayArgs)(nil)).Elem()
}

type GatewayInput interface {
	pulumi.Input

	ToGatewayOutput() GatewayOutput
	ToGatewayOutputWithContext(ctx context.Context) GatewayOutput
}

func (*Gateway) ElementType() reflect.Type {
	return reflect.TypeOf((**Gateway)(nil)).Elem()
}

func (i *Gateway) ToGatewayOutput() GatewayOutput {
	return i.ToGatewayOutputWithContext(context.Background())
}

func (i *Gateway) ToGatewayOutputWithContext(ctx context.Context) GatewayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GatewayOutput)
}

// GatewayArrayInput is an input type that accepts GatewayArray and GatewayArrayOutput values.
// You can construct a concrete instance of `GatewayArrayInput` via:
//
//          GatewayArray{ GatewayArgs{...} }
type GatewayArrayInput interface {
	pulumi.Input

	ToGatewayArrayOutput() GatewayArrayOutput
	ToGatewayArrayOutputWithContext(context.Context) GatewayArrayOutput
}

type GatewayArray []GatewayInput

func (GatewayArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Gateway)(nil)).Elem()
}

func (i GatewayArray) ToGatewayArrayOutput() GatewayArrayOutput {
	return i.ToGatewayArrayOutputWithContext(context.Background())
}

func (i GatewayArray) ToGatewayArrayOutputWithContext(ctx context.Context) GatewayArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GatewayArrayOutput)
}

// GatewayMapInput is an input type that accepts GatewayMap and GatewayMapOutput values.
// You can construct a concrete instance of `GatewayMapInput` via:
//
//          GatewayMap{ "key": GatewayArgs{...} }
type GatewayMapInput interface {
	pulumi.Input

	ToGatewayMapOutput() GatewayMapOutput
	ToGatewayMapOutputWithContext(context.Context) GatewayMapOutput
}

type GatewayMap map[string]GatewayInput

func (GatewayMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Gateway)(nil)).Elem()
}

func (i GatewayMap) ToGatewayMapOutput() GatewayMapOutput {
	return i.ToGatewayMapOutputWithContext(context.Background())
}

func (i GatewayMap) ToGatewayMapOutputWithContext(ctx context.Context) GatewayMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(GatewayMapOutput)
}

type GatewayOutput struct{ *pulumi.OutputState }

func (GatewayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Gateway)(nil)).Elem()
}

func (o GatewayOutput) ToGatewayOutput() GatewayOutput {
	return o
}

func (o GatewayOutput) ToGatewayOutputWithContext(ctx context.Context) GatewayOutput {
	return o
}

type GatewayArrayOutput struct{ *pulumi.OutputState }

func (GatewayArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Gateway)(nil)).Elem()
}

func (o GatewayArrayOutput) ToGatewayArrayOutput() GatewayArrayOutput {
	return o
}

func (o GatewayArrayOutput) ToGatewayArrayOutputWithContext(ctx context.Context) GatewayArrayOutput {
	return o
}

func (o GatewayArrayOutput) Index(i pulumi.IntInput) GatewayOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Gateway {
		return vs[0].([]*Gateway)[vs[1].(int)]
	}).(GatewayOutput)
}

type GatewayMapOutput struct{ *pulumi.OutputState }

func (GatewayMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Gateway)(nil)).Elem()
}

func (o GatewayMapOutput) ToGatewayMapOutput() GatewayMapOutput {
	return o
}

func (o GatewayMapOutput) ToGatewayMapOutputWithContext(ctx context.Context) GatewayMapOutput {
	return o
}

func (o GatewayMapOutput) MapIndex(k pulumi.StringInput) GatewayOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Gateway {
		return vs[0].(map[string]*Gateway)[vs[1].(string)]
	}).(GatewayOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*GatewayInput)(nil)).Elem(), &Gateway{})
	pulumi.RegisterInputType(reflect.TypeOf((*GatewayArrayInput)(nil)).Elem(), GatewayArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*GatewayMapInput)(nil)).Elem(), GatewayMap{})
	pulumi.RegisterOutputType(GatewayOutput{})
	pulumi.RegisterOutputType(GatewayArrayOutput{})
	pulumi.RegisterOutputType(GatewayMapOutput{})
}
