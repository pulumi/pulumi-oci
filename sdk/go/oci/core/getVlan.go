// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package core

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Vlan resource in Oracle Cloud Infrastructure Core service.
//
// Gets the specified VLAN's information.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/core"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := core.GetVlan(ctx, &core.GetVlanArgs{
//				VlanId: testVlanOciCoreVlan.Id,
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupVlan(ctx *pulumi.Context, args *LookupVlanArgs, opts ...pulumi.InvokeOption) (*LookupVlanResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv LookupVlanResult
	err := ctx.Invoke("oci:Core/getVlan:getVlan", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getVlan.
type LookupVlanArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN.
	VlanId string `pulumi:"vlanId"`
}

// A collection of values returned by getVlan.
type LookupVlanResult struct {
	// The VLAN's availability domain. This attribute will be null if this is a regional VLAN rather than an AD-specific VLAN.  Example: `Uocm:PHX-AD-1`
	AvailabilityDomain string `pulumi:"availabilityDomain"`
	// The range of IPv4 addresses that will be used for layer 3 communication with hosts outside the VLAN.  Example: `192.168.1.0/24`
	CidrBlock string `pulumi:"cidrBlock"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the VLAN.
	CompartmentId string `pulumi:"compartmentId"`
	// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
	DisplayName string `pulumi:"displayName"`
	// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// The VLAN's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
	Id string `pulumi:"id"`
	// A list of the OCIDs of the network security groups (NSGs) to use with this VLAN. All VNICs in the VLAN belong to these NSGs. For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/).
	NsgIds []string `pulumi:"nsgIds"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table that the VLAN uses.
	RouteTableId string `pulumi:"routeTableId"`
	// The VLAN's current state.
	State string `pulumi:"state"`
	// The date and time the VLAN was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
	TimeCreated string `pulumi:"timeCreated"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the VLAN is in.
	VcnId  string `pulumi:"vcnId"`
	VlanId string `pulumi:"vlanId"`
	// The IEEE 802.1Q VLAN tag of this VLAN.  Example: `100`
	VlanTag int `pulumi:"vlanTag"`
}

func LookupVlanOutput(ctx *pulumi.Context, args LookupVlanOutputArgs, opts ...pulumi.InvokeOption) LookupVlanResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (LookupVlanResultOutput, error) {
			args := v.(LookupVlanArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:Core/getVlan:getVlan", args, LookupVlanResultOutput{}, options).(LookupVlanResultOutput), nil
		}).(LookupVlanResultOutput)
}

// A collection of arguments for invoking getVlan.
type LookupVlanOutputArgs struct {
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VLAN.
	VlanId pulumi.StringInput `pulumi:"vlanId"`
}

func (LookupVlanOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupVlanArgs)(nil)).Elem()
}

// A collection of values returned by getVlan.
type LookupVlanResultOutput struct{ *pulumi.OutputState }

func (LookupVlanResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupVlanResult)(nil)).Elem()
}

func (o LookupVlanResultOutput) ToLookupVlanResultOutput() LookupVlanResultOutput {
	return o
}

func (o LookupVlanResultOutput) ToLookupVlanResultOutputWithContext(ctx context.Context) LookupVlanResultOutput {
	return o
}

// The VLAN's availability domain. This attribute will be null if this is a regional VLAN rather than an AD-specific VLAN.  Example: `Uocm:PHX-AD-1`
func (o LookupVlanResultOutput) AvailabilityDomain() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVlanResult) string { return v.AvailabilityDomain }).(pulumi.StringOutput)
}

// The range of IPv4 addresses that will be used for layer 3 communication with hosts outside the VLAN.  Example: `192.168.1.0/24`
func (o LookupVlanResultOutput) CidrBlock() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVlanResult) string { return v.CidrBlock }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment containing the VLAN.
func (o LookupVlanResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVlanResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Operations.CostCenter": "42"}`
func (o LookupVlanResultOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupVlanResult) map[string]string { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// A user-friendly name. Does not have to be unique, and it's changeable. Avoid entering confidential information.
func (o LookupVlanResultOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVlanResult) string { return v.DisplayName }).(pulumi.StringOutput)
}

// Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm).  Example: `{"Department": "Finance"}`
func (o LookupVlanResultOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v LookupVlanResult) map[string]string { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// The VLAN's Oracle ID ([OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm)).
func (o LookupVlanResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVlanResult) string { return v.Id }).(pulumi.StringOutput)
}

// A list of the OCIDs of the network security groups (NSGs) to use with this VLAN. All VNICs in the VLAN belong to these NSGs. For more information about NSGs, see [NetworkSecurityGroup](https://docs.cloud.oracle.com/iaas/api/#/en/iaas/latest/NetworkSecurityGroup/).
func (o LookupVlanResultOutput) NsgIds() pulumi.StringArrayOutput {
	return o.ApplyT(func(v LookupVlanResult) []string { return v.NsgIds }).(pulumi.StringArrayOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the route table that the VLAN uses.
func (o LookupVlanResultOutput) RouteTableId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVlanResult) string { return v.RouteTableId }).(pulumi.StringOutput)
}

// The VLAN's current state.
func (o LookupVlanResultOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVlanResult) string { return v.State }).(pulumi.StringOutput)
}

// The date and time the VLAN was created, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).  Example: `2016-08-25T21:10:29.600Z`
func (o LookupVlanResultOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVlanResult) string { return v.TimeCreated }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the VCN the VLAN is in.
func (o LookupVlanResultOutput) VcnId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVlanResult) string { return v.VcnId }).(pulumi.StringOutput)
}

func (o LookupVlanResultOutput) VlanId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupVlanResult) string { return v.VlanId }).(pulumi.StringOutput)
}

// The IEEE 802.1Q VLAN tag of this VLAN.  Example: `100`
func (o LookupVlanResultOutput) VlanTag() pulumi.IntOutput {
	return o.ApplyT(func(v LookupVlanResult) int { return v.VlanTag }).(pulumi.IntOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupVlanResultOutput{})
}
