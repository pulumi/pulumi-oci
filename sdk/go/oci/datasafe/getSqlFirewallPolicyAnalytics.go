// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumix"
)

// This data source provides the list of Sql Firewall Policy Analytics in Oracle Cloud Infrastructure Data Safe service.
//
// Gets a list of aggregated SQL firewall policy details.
//
// The parameter `accessLevel` specifies whether to return only those compartments for which the
// requestor has INSPECT permissions on at least one resource directly
// or indirectly (ACCESSIBLE) (the resource can be in a subcompartment) or to return Not Authorized if
// principal doesn't have access to even one of the child compartments. This is valid only when
// `compartmentIdInSubtree` is set to `true`.
//
// The parameter `compartmentIdInSubtree` applies when you perform SummarizedSqlFirewallPolicyInfo on the specified
// `compartmentId` and when it is set to true, the entire hierarchy of compartments can be returned.
// To get a full list of all compartments and subcompartments in the tenancy (root compartment),
// set the parameter `compartmentIdInSubtree` to true and `accessLevel` to ACCESSIBLE.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/DataSafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := DataSafe.GetSqlFirewallPolicyAnalytics(ctx, &datasafe.GetSqlFirewallPolicyAnalyticsArgs{
//				CompartmentId:          _var.Compartment_id,
//				AccessLevel:            pulumi.StringRef(_var.Sql_firewall_policy_analytic_access_level),
//				CompartmentIdInSubtree: pulumi.BoolRef(_var.Sql_firewall_policy_analytic_compartment_id_in_subtree),
//				GroupBies:              _var.Sql_firewall_policy_analytic_group_by,
//				SecurityPolicyId:       pulumi.StringRef(oci_data_safe_security_policy.Test_security_policy.Id),
//				State:                  pulumi.StringRef(_var.Sql_firewall_policy_analytic_state),
//				TimeEnded:              pulumi.StringRef(_var.Sql_firewall_policy_analytic_time_ended),
//				TimeStarted:            pulumi.StringRef(_var.Sql_firewall_policy_analytic_time_started),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSqlFirewallPolicyAnalytics(ctx *pulumi.Context, args *GetSqlFirewallPolicyAnalyticsArgs, opts ...pulumi.InvokeOption) (*GetSqlFirewallPolicyAnalyticsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetSqlFirewallPolicyAnalyticsResult
	err := ctx.Invoke("oci:DataSafe/getSqlFirewallPolicyAnalytics:getSqlFirewallPolicyAnalytics", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSqlFirewallPolicyAnalytics.
type GetSqlFirewallPolicyAnalyticsArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel *string `pulumi:"accessLevel"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId string `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree *bool                                 `pulumi:"compartmentIdInSubtree"`
	Filters                []GetSqlFirewallPolicyAnalyticsFilter `pulumi:"filters"`
	// The group by parameter to summarize SQL firewall policy aggregation.
	GroupBies []string `pulumi:"groupBies"`
	// An optional filter to return only resources that match the specified OCID of the security policy resource.
	SecurityPolicyId *string `pulumi:"securityPolicyId"`
	// The current state of the SQL firewall policy.
	State *string `pulumi:"state"`
	// An optional filter to return the summary of the SQL firewall policies created before the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeEnded *string `pulumi:"timeEnded"`
	// An optional filter to return the summary of the SQL firewall policies created after the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeStarted *string `pulumi:"timeStarted"`
}

// A collection of values returned by getSqlFirewallPolicyAnalytics.
type GetSqlFirewallPolicyAnalyticsResult struct {
	AccessLevel            *string                               `pulumi:"accessLevel"`
	CompartmentId          string                                `pulumi:"compartmentId"`
	CompartmentIdInSubtree *bool                                 `pulumi:"compartmentIdInSubtree"`
	Filters                []GetSqlFirewallPolicyAnalyticsFilter `pulumi:"filters"`
	GroupBies              []string                              `pulumi:"groupBies"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// The OCID of the security policy corresponding to the SQL firewall policy.
	SecurityPolicyId *string `pulumi:"securityPolicyId"`
	// The list of sql_firewall_policy_analytics_collection.
	SqlFirewallPolicyAnalyticsCollections []GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollection `pulumi:"sqlFirewallPolicyAnalyticsCollections"`
	// The current state of the SQL firewall policy.
	State       *string `pulumi:"state"`
	TimeEnded   *string `pulumi:"timeEnded"`
	TimeStarted *string `pulumi:"timeStarted"`
}

func GetSqlFirewallPolicyAnalyticsOutput(ctx *pulumi.Context, args GetSqlFirewallPolicyAnalyticsOutputArgs, opts ...pulumi.InvokeOption) GetSqlFirewallPolicyAnalyticsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetSqlFirewallPolicyAnalyticsResult, error) {
			args := v.(GetSqlFirewallPolicyAnalyticsArgs)
			r, err := GetSqlFirewallPolicyAnalytics(ctx, &args, opts...)
			var s GetSqlFirewallPolicyAnalyticsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetSqlFirewallPolicyAnalyticsResultOutput)
}

// A collection of arguments for invoking getSqlFirewallPolicyAnalytics.
type GetSqlFirewallPolicyAnalyticsOutputArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel pulumi.StringPtrInput `pulumi:"accessLevel"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree pulumi.BoolPtrInput                           `pulumi:"compartmentIdInSubtree"`
	Filters                GetSqlFirewallPolicyAnalyticsFilterArrayInput `pulumi:"filters"`
	// The group by parameter to summarize SQL firewall policy aggregation.
	GroupBies pulumi.StringArrayInput `pulumi:"groupBies"`
	// An optional filter to return only resources that match the specified OCID of the security policy resource.
	SecurityPolicyId pulumi.StringPtrInput `pulumi:"securityPolicyId"`
	// The current state of the SQL firewall policy.
	State pulumi.StringPtrInput `pulumi:"state"`
	// An optional filter to return the summary of the SQL firewall policies created before the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeEnded pulumi.StringPtrInput `pulumi:"timeEnded"`
	// An optional filter to return the summary of the SQL firewall policies created after the date-time specified, in the format defined by [RFC3339](https://tools.ietf.org/html/rfc3339).
	TimeStarted pulumi.StringPtrInput `pulumi:"timeStarted"`
}

func (GetSqlFirewallPolicyAnalyticsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSqlFirewallPolicyAnalyticsArgs)(nil)).Elem()
}

// A collection of values returned by getSqlFirewallPolicyAnalytics.
type GetSqlFirewallPolicyAnalyticsResultOutput struct{ *pulumi.OutputState }

func (GetSqlFirewallPolicyAnalyticsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSqlFirewallPolicyAnalyticsResult)(nil)).Elem()
}

func (o GetSqlFirewallPolicyAnalyticsResultOutput) ToGetSqlFirewallPolicyAnalyticsResultOutput() GetSqlFirewallPolicyAnalyticsResultOutput {
	return o
}

func (o GetSqlFirewallPolicyAnalyticsResultOutput) ToGetSqlFirewallPolicyAnalyticsResultOutputWithContext(ctx context.Context) GetSqlFirewallPolicyAnalyticsResultOutput {
	return o
}

func (o GetSqlFirewallPolicyAnalyticsResultOutput) ToOutput(ctx context.Context) pulumix.Output[GetSqlFirewallPolicyAnalyticsResult] {
	return pulumix.Output[GetSqlFirewallPolicyAnalyticsResult]{
		OutputState: o.OutputState,
	}
}

func (o GetSqlFirewallPolicyAnalyticsResultOutput) AccessLevel() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSqlFirewallPolicyAnalyticsResult) *string { return v.AccessLevel }).(pulumi.StringPtrOutput)
}

func (o GetSqlFirewallPolicyAnalyticsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSqlFirewallPolicyAnalyticsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetSqlFirewallPolicyAnalyticsResultOutput) CompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetSqlFirewallPolicyAnalyticsResult) *bool { return v.CompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

func (o GetSqlFirewallPolicyAnalyticsResultOutput) Filters() GetSqlFirewallPolicyAnalyticsFilterArrayOutput {
	return o.ApplyT(func(v GetSqlFirewallPolicyAnalyticsResult) []GetSqlFirewallPolicyAnalyticsFilter { return v.Filters }).(GetSqlFirewallPolicyAnalyticsFilterArrayOutput)
}

func (o GetSqlFirewallPolicyAnalyticsResultOutput) GroupBies() pulumi.StringArrayOutput {
	return o.ApplyT(func(v GetSqlFirewallPolicyAnalyticsResult) []string { return v.GroupBies }).(pulumi.StringArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSqlFirewallPolicyAnalyticsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSqlFirewallPolicyAnalyticsResult) string { return v.Id }).(pulumi.StringOutput)
}

// The OCID of the security policy corresponding to the SQL firewall policy.
func (o GetSqlFirewallPolicyAnalyticsResultOutput) SecurityPolicyId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSqlFirewallPolicyAnalyticsResult) *string { return v.SecurityPolicyId }).(pulumi.StringPtrOutput)
}

// The list of sql_firewall_policy_analytics_collection.
func (o GetSqlFirewallPolicyAnalyticsResultOutput) SqlFirewallPolicyAnalyticsCollections() GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionArrayOutput {
	return o.ApplyT(func(v GetSqlFirewallPolicyAnalyticsResult) []GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollection {
		return v.SqlFirewallPolicyAnalyticsCollections
	}).(GetSqlFirewallPolicyAnalyticsSqlFirewallPolicyAnalyticsCollectionArrayOutput)
}

// The current state of the SQL firewall policy.
func (o GetSqlFirewallPolicyAnalyticsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSqlFirewallPolicyAnalyticsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func (o GetSqlFirewallPolicyAnalyticsResultOutput) TimeEnded() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSqlFirewallPolicyAnalyticsResult) *string { return v.TimeEnded }).(pulumi.StringPtrOutput)
}

func (o GetSqlFirewallPolicyAnalyticsResultOutput) TimeStarted() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSqlFirewallPolicyAnalyticsResult) *string { return v.TimeStarted }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSqlFirewallPolicyAnalyticsResultOutput{})
}