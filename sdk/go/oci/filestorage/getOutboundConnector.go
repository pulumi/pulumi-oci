// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package filestorage

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Outbound Connector resource in Oracle Cloud Infrastructure File Storage service.
//
// Gets the specified outbound connector's information.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/filestorage"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := filestorage.GetOutboundConnector(ctx, &filestorage.GetOutboundConnectorArgs{
//				OutboundConnectorId: testOutboundConnectorOciFileStorageOutboundConnector.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupOutboundConnector(ctx *pulumi.Context, args *LookupOutboundConnectorArgs, opts ...pulumi.InvokeOption) (*LookupOutboundConnectorResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupOutboundConnectorResult
	err := ctx.Invoke("oci:FileStorage/getOutboundConnector:getOutboundConnector", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getOutboundConnector.
type LookupOutboundConnectorArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the outbound connector.
	OutboundConnectorId string `pulumi:"outboundConnectorId"`
}

// A collection of values returned by getOutboundConnector.
type LookupOutboundConnectorResult struct {
	// The availability domain the outbound connector is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The LDAP Distinguished Name of the account.
	BindDistinguishedName string `pulumi:"bindDistinguishedName"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the outbound connector.
	CompartmentId string `pulumi:"compartmentId"`
	// The account type of this outbound connector.
	ConnectorType string `pulumi:"connectorType"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My outbound connector`
	DisplayName string `pulumi:"displayName"`
	// Array of server endpoints to use when connecting with the LDAP bind account.
	Endpoints []GetOutboundConnectorEndpoint `pulumi:"endpoints"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the outbound connector.
	Id             string `pulumi:"id"`
	IsLockOverride bool   `pulumi:"isLockOverride"`
	// Locks associated with this resource.
	Locks               []GetOutboundConnectorLock `pulumi:"locks"`
	OutboundConnectorId string                     `pulumi:"outboundConnectorId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the password for the LDAP bind account in the Vault.
	PasswordSecretId string `pulumi:"passwordSecretId"`
	// Version of the password secret in the Vault to use.
	PasswordSecretVersion int `pulumi:"passwordSecretVersion"`
	// The current state of this outbound connector.
	State string `pulumi:"state"`
	// System tags for this resource. System tags are applied to resources by internal Oracle Cloud Infrastructure services.
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the outbound connector was created in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
}

func LookupOutboundConnectorOutput(ctx *pulumi.Context, args LookupOutboundConnectorOutputArgs, opts ...pulumi.InvokeOption) LookupOutboundConnectorResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupOutboundConnectorResultOutput, error) {
			args := v.(LookupOutboundConnectorArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:FileStorage/getOutboundConnector:getOutboundConnector", args, LookupOutboundConnectorResultOutput{}, options).(LookupOutboundConnectorResultOutput), nil
		}).(LookupOutboundConnectorResultOutput)
}

// A collection of arguments for invoking getOutboundConnector.
type LookupOutboundConnectorOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the outbound connector.
	OutboundConnectorId pulumi.StringInput `pulumi:"outboundConnectorId"`
}

func (LookupOutboundConnectorOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupOutboundConnectorArgs)(nil)).Elem()
}

// A collection of values returned by getOutboundConnector.
type LookupOutboundConnectorResultOutput struct{ *pulumi.OutputState }

func (LookupOutboundConnectorResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupOutboundConnectorResult)(nil)).Elem()
}

func (o LookupOutboundConnectorResultOutput) ToLookupOutboundConnectorResultOutput() LookupOutboundConnectorResultOutput {
	return o
}

func (o LookupOutboundConnectorResultOutput) ToLookupOutboundConnectorResultOutputWithContext(ctx context.Context) LookupOutboundConnectorResultOutput {
	return o
}

// The availability domain the outbound connector is in. May be unset as a blank or NULL value.  Example: `Uocm:PHX-AD-1`
func (o LookupOutboundConnectorResultOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) string { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// The LDAP Distinguished Name of the account.
func (o LookupOutboundConnectorResultOutput) BindDistinguishedName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) string { return v.BindDistinguishedName }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment that contains the outbound connector.
func (o LookupOutboundConnectorResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The account type of this outbound connector.
func (o LookupOutboundConnectorResultOutput) ConnectorType() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) string { return v.ConnectorType }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Operations.CostCenter": "42"}`
func (o LookupOutboundConnectorResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// A user-friendly name. It does not have to be unique, and it is changeable. Avoid entering confidential information.  Example: `My outbound connector`
func (o LookupOutboundConnectorResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Array of server endpoints to use when connecting with the LDAP bind account.
func (o LookupOutboundConnectorResultOutput) Endpoints() GetOutboundConnectorEndpointArrayOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) []GetOutboundConnectorEndpoint { return v.Endpoints }).(GetOutboundConnectorEndpointArrayOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{"Department": "Finance"}`
func (o LookupOutboundConnectorResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the outbound connector.
func (o LookupOutboundConnectorResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o LookupOutboundConnectorResultOutput) IsLockOverride() pulumi.BoolOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) bool { return v.IsLockOverride }).(pulumi.BoolOutput)
}

// Locks associated with this resource.
func (o LookupOutboundConnectorResultOutput) Locks() GetOutboundConnectorLockArrayOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) []GetOutboundConnectorLock { return v.Locks }).(GetOutboundConnectorLockArrayOutput)
}

func (o LookupOutboundConnectorResultOutput) OutboundConnectorId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) string { return v.OutboundConnectorId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the password for the LDAP bind account in the Vault.
func (o LookupOutboundConnectorResultOutput) PasswordSecretId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) string { return v.PasswordSecretId }).(pulumi.StringOutput)
}

// Version of the password secret in the Vault to use.
func (o LookupOutboundConnectorResultOutput) PasswordSecretVersion() pulumi.IntOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) int { return v.PasswordSecretVersion }).(pulumi.IntOutput)
}

// The current state of this outbound connector.
func (o LookupOutboundConnectorResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) string { return v.State }).(pulumi.StringOutput)
}

// System tags for this resource. System tags are applied to resources by internal Oracle Cloud Infrastructure services.
func (o LookupOutboundConnectorResultOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) map[string]string { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the outbound connector was created in [RFC 3339](https://tools.ietf.org/rfc/rfc3339) timestamp format.  Example: `2016-08-25T21:10:29.600Z`
func (o LookupOutboundConnectorResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupOutboundConnectorResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupOutboundConnectorResultOutput{})
}
