// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package dns

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides details about a specific Rrset resource in Oracle Cloud Infrastructure DNS service.
//
// Gets a list of all records in the specified RRSet. The results are sorted by `recordHash` by default. For
// private zones, the scope query parameter is required with a value of `PRIVATE`. When the zone name is
// provided as a path parameter and `PRIVATE` is used for the scope query parameter then the viewId query
// parameter is required.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Dns"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Dns.GetRrset(ctx, &dns.GetRrsetArgs{
//				Domain:        _var.Rrset_domain,
//				Rtype:         _var.Rrset_rtype,
//				ZoneNameOrId:  oci_dns_zone.Test_zone.Id,
//				CompartmentId: pulumi.StringRef(_var.Compartment_id),
//				Scope:         pulumi.StringRef(_var.Rrset_scope),
//				ViewId:        pulumi.StringRef(oci_dns_view.Test_view.Id),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func LookupRrset(ctx *pulumi.Context, args *LookupRrsetArgs, opts ...pulumi.InvokeOption) (*LookupRrsetResult, error) {
	var rv LookupRrsetResult
	err := ctx.Invoke("oci:Dns/getRrset:getRrset", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getRrset.
type LookupRrsetArgs struct {
	// The OCID of the compartment the resource belongs to.
	CompartmentId *string `pulumi:"compartmentId"`
	// The target fully-qualified domain name (FQDN) within the target zone.
	Domain string `pulumi:"domain"`
	// The type of the target RRSet within the target zone.
	Rtype string `pulumi:"rtype"`
	// Specifies to operate only on resources that have a matching DNS scope.
	// This value will be null for zones in the global DNS and `PRIVATE` when listing private Rrsets.
	Scope *string `pulumi:"scope"`
	// The OCID of the view the resource is associated with.
	ViewId *string `pulumi:"viewId"`
	// The name or OCID of the target zone.
	ZoneNameOrId string `pulumi:"zoneNameOrId"`
	// The version of the zone for which data is requested.
	ZoneVersion *string `pulumi:"zoneVersion"`
}

// A collection of values returned by getRrset.
type LookupRrsetResult struct {
	CompartmentId *string `pulumi:"compartmentId"`
	// The fully qualified domain name where the record can be located.
	Domain string         `pulumi:"domain"`
	Id     string         `pulumi:"id"`
	Items  []GetRrsetItem `pulumi:"items"`
	// The type of DNS record, such as A or CNAME. For more information, see [Resource Record (RR) TYPEs](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4).
	Rtype        string  `pulumi:"rtype"`
	Scope        *string `pulumi:"scope"`
	ViewId       *string `pulumi:"viewId"`
	ZoneNameOrId string  `pulumi:"zoneNameOrId"`
	ZoneVersion  *string `pulumi:"zoneVersion"`
}

func LookupRrsetOutput(ctx *pulumi.Context, args LookupRrsetOutputArgs, opts ...pulumi.InvokeOption) LookupRrsetResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (LookupRrsetResult, error) {
			args := v.(LookupRrsetArgs)
			r, err := LookupRrset(ctx, &args, opts...)
			var s LookupRrsetResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(LookupRrsetResultOutput)
}

// A collection of arguments for invoking getRrset.
type LookupRrsetOutputArgs struct {
	// The OCID of the compartment the resource belongs to.
	CompartmentId pulumi.StringPtrInput `pulumi:"compartmentId"`
	// The target fully-qualified domain name (FQDN) within the target zone.
	Domain pulumi.StringInput `pulumi:"domain"`
	// The type of the target RRSet within the target zone.
	Rtype pulumi.StringInput `pulumi:"rtype"`
	// Specifies to operate only on resources that have a matching DNS scope.
	// This value will be null for zones in the global DNS and `PRIVATE` when listing private Rrsets.
	Scope pulumi.StringPtrInput `pulumi:"scope"`
	// The OCID of the view the resource is associated with.
	ViewId pulumi.StringPtrInput `pulumi:"viewId"`
	// The name or OCID of the target zone.
	ZoneNameOrId pulumi.StringInput `pulumi:"zoneNameOrId"`
	// The version of the zone for which data is requested.
	ZoneVersion pulumi.StringPtrInput `pulumi:"zoneVersion"`
}

func (LookupRrsetOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupRrsetArgs)(nil)).Elem()
}

// A collection of values returned by getRrset.
type LookupRrsetResultOutput struct{ *pulumi.OutputState }

func (LookupRrsetResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*LookupRrsetResult)(nil)).Elem()
}

func (o LookupRrsetResultOutput) ToLookupRrsetResultOutput() LookupRrsetResultOutput {
	return o
}

func (o LookupRrsetResultOutput) ToLookupRrsetResultOutputWithContext(ctx context.Context) LookupRrsetResultOutput {
	return o
}

func (o LookupRrsetResultOutput) CompartmentId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupRrsetResult) *string { return v.CompartmentId }).(pulumi.StringPtrOutput)
}

// The fully qualified domain name where the record can be located.
func (o LookupRrsetResultOutput) Domain() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRrsetResult) string { return v.Domain }).(pulumi.StringOutput)
}

func (o LookupRrsetResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRrsetResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o LookupRrsetResultOutput) Items() GetRrsetItemArrayOutput {
	return o.ApplyT(func(v LookupRrsetResult) []GetRrsetItem { return v.Items }).(GetRrsetItemArrayOutput)
}

// The type of DNS record, such as A or CNAME. For more information, see [Resource Record (RR) TYPEs](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4).
func (o LookupRrsetResultOutput) Rtype() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRrsetResult) string { return v.Rtype }).(pulumi.StringOutput)
}

func (o LookupRrsetResultOutput) Scope() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupRrsetResult) *string { return v.Scope }).(pulumi.StringPtrOutput)
}

func (o LookupRrsetResultOutput) ViewId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupRrsetResult) *string { return v.ViewId }).(pulumi.StringPtrOutput)
}

func (o LookupRrsetResultOutput) ZoneNameOrId() pulumi.StringOutput {
	return o.ApplyT(func(v LookupRrsetResult) string { return v.ZoneNameOrId }).(pulumi.StringOutput)
}

func (o LookupRrsetResultOutput) ZoneVersion() pulumi.StringPtrOutput {
	return o.ApplyT(func(v LookupRrsetResult) *string { return v.ZoneVersion }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(LookupRrsetResultOutput{})
}