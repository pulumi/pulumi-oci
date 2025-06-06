// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package datasafe

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Security Assessment Finding Analytics in Oracle Cloud Infrastructure Data Safe service.
//
// Gets a list of findings aggregated details in the specified compartment. This provides information about the overall state
// of security assessment findings. You can use groupBy to get the count of findings under a certain risk level and with a certain findingKey,
// and as well as get the list of the targets that match the condition.
// This data is especially useful content for the statistic chart or to support analytics.
//
// When you perform the ListFindingAnalytics operation, if the parameter compartmentIdInSubtree is set to "true," and if the
// parameter accessLevel is set to ACCESSIBLE, then the operation returns statistics from the compartments in which the requestor has INSPECT
// permissions on at least one resource, directly or indirectly (in subcompartments). If the operation is performed at the
// root compartment and the requestor does not have access to at least one subcompartment of the compartment specified by
// compartmentId, then "Not Authorized" is returned.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/datasafe"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := datasafe.GetSecurityAssessmentFindingAnalytics(ctx, &datasafe.GetSecurityAssessmentFindingAnalyticsArgs{
//				CompartmentId:          compartmentId,
//				AccessLevel:            pulumi.StringRef(securityAssessmentFindingAnalyticAccessLevel),
//				CompartmentIdInSubtree: pulumi.BoolRef(securityAssessmentFindingAnalyticCompartmentIdInSubtree),
//				FindingKey:             pulumi.StringRef(securityAssessmentFindingAnalyticFindingKey),
//				GroupBy:                pulumi.StringRef(securityAssessmentFindingAnalyticGroupBy),
//				IsTopFinding:           pulumi.BoolRef(securityAssessmentFindingAnalyticIsTopFinding),
//				Severity:               pulumi.StringRef(securityAssessmentFindingAnalyticSeverity),
//				TopFindingStatus:       pulumi.StringRef(securityAssessmentFindingAnalyticTopFindingStatus),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSecurityAssessmentFindingAnalytics(ctx *pulumi.Context, args *GetSecurityAssessmentFindingAnalyticsArgs, opts ...pulumi.InvokeOption) (*GetSecurityAssessmentFindingAnalyticsResult, error) {
	opts = internal.PkgInvokeDefaultOpts(opts)
	var rv GetSecurityAssessmentFindingAnalyticsResult
	err := ctx.Invoke("oci:DataSafe/getSecurityAssessmentFindingAnalytics:getSecurityAssessmentFindingAnalytics", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSecurityAssessmentFindingAnalytics.
type GetSecurityAssessmentFindingAnalyticsArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel *string `pulumi:"accessLevel"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId string `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree *bool                                         `pulumi:"compartmentIdInSubtree"`
	Filters                []GetSecurityAssessmentFindingAnalyticsFilter `pulumi:"filters"`
	// The unique key that identifies the finding. It is a string and unique within a security assessment.
	FindingKey *string `pulumi:"findingKey"`
	// Attribute by which the finding analytics data should be grouped.
	GroupBy *string `pulumi:"groupBy"`
	// A filter to return only the findings that are marked as top findings.
	IsTopFinding *bool `pulumi:"isTopFinding"`
	// A filter to return only findings of a particular risk level.
	Severity *string `pulumi:"severity"`
	// An optional filter to return only the top finding that match the specified status.
	TopFindingStatus *string `pulumi:"topFindingStatus"`
}

// A collection of values returned by getSecurityAssessmentFindingAnalytics.
type GetSecurityAssessmentFindingAnalyticsResult struct {
	AccessLevel            *string                                       `pulumi:"accessLevel"`
	CompartmentId          string                                        `pulumi:"compartmentId"`
	CompartmentIdInSubtree *bool                                         `pulumi:"compartmentIdInSubtree"`
	Filters                []GetSecurityAssessmentFindingAnalyticsFilter `pulumi:"filters"`
	// The list of finding_analytics_collection.
	FindingAnalyticsCollections []GetSecurityAssessmentFindingAnalyticsFindingAnalyticsCollection `pulumi:"findingAnalyticsCollections"`
	FindingKey                  *string                                                           `pulumi:"findingKey"`
	GroupBy                     *string                                                           `pulumi:"groupBy"`
	// The provider-assigned unique ID for this managed resource.
	Id           string `pulumi:"id"`
	IsTopFinding *bool  `pulumi:"isTopFinding"`
	// The severity (risk level) of the finding.
	Severity *string `pulumi:"severity"`
	// The status of the top finding.  All findings will have "severity" to indicate the risk level, but only top findings will have "status".  Possible status: Pass / Risk (Low, Medium, High)/ Evaluate / Advisory / Deferred Instead of having "Low, Medium, High" in severity, "Risk" will include these three situations in status.
	TopFindingStatus *string `pulumi:"topFindingStatus"`
}

func GetSecurityAssessmentFindingAnalyticsOutput(ctx *pulumi.Context, args GetSecurityAssessmentFindingAnalyticsOutputArgs, opts ...pulumi.InvokeOption) GetSecurityAssessmentFindingAnalyticsResultOutput {
	return pulumi.ToOutputWithContext(ctx.Context(), args).
		ApplyT(func(v interface{}) (GetSecurityAssessmentFindingAnalyticsResultOutput, error) {
			args := v.(GetSecurityAssessmentFindingAnalyticsArgs)
			options := pulumi.InvokeOutputOptions{InvokeOptions: internal.PkgInvokeDefaultOpts(opts)}
			return ctx.InvokeOutput("oci:DataSafe/getSecurityAssessmentFindingAnalytics:getSecurityAssessmentFindingAnalytics", args, GetSecurityAssessmentFindingAnalyticsResultOutput{}, options).(GetSecurityAssessmentFindingAnalyticsResultOutput), nil
		}).(GetSecurityAssessmentFindingAnalyticsResultOutput)
}

// A collection of arguments for invoking getSecurityAssessmentFindingAnalytics.
type GetSecurityAssessmentFindingAnalyticsOutputArgs struct {
	// Valid values are RESTRICTED and ACCESSIBLE. Default is RESTRICTED. Setting this to ACCESSIBLE returns only those compartments for which the user has INSPECT permissions directly or indirectly (permissions can be on a resource in a subcompartment). When set to RESTRICTED permissions are checked and no partial results are displayed.
	AccessLevel pulumi.StringPtrInput `pulumi:"accessLevel"`
	// A filter to return only resources that match the specified compartment OCID.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// Default is false. When set to true, the hierarchy of compartments is traversed and all compartments and subcompartments in the tenancy are returned. Depends on the 'accessLevel' setting.
	CompartmentIdInSubtree pulumi.BoolPtrInput                                   `pulumi:"compartmentIdInSubtree"`
	Filters                GetSecurityAssessmentFindingAnalyticsFilterArrayInput `pulumi:"filters"`
	// The unique key that identifies the finding. It is a string and unique within a security assessment.
	FindingKey pulumi.StringPtrInput `pulumi:"findingKey"`
	// Attribute by which the finding analytics data should be grouped.
	GroupBy pulumi.StringPtrInput `pulumi:"groupBy"`
	// A filter to return only the findings that are marked as top findings.
	IsTopFinding pulumi.BoolPtrInput `pulumi:"isTopFinding"`
	// A filter to return only findings of a particular risk level.
	Severity pulumi.StringPtrInput `pulumi:"severity"`
	// An optional filter to return only the top finding that match the specified status.
	TopFindingStatus pulumi.StringPtrInput `pulumi:"topFindingStatus"`
}

func (GetSecurityAssessmentFindingAnalyticsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecurityAssessmentFindingAnalyticsArgs)(nil)).Elem()
}

// A collection of values returned by getSecurityAssessmentFindingAnalytics.
type GetSecurityAssessmentFindingAnalyticsResultOutput struct{ *pulumi.OutputState }

func (GetSecurityAssessmentFindingAnalyticsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecurityAssessmentFindingAnalyticsResult)(nil)).Elem()
}

func (o GetSecurityAssessmentFindingAnalyticsResultOutput) ToGetSecurityAssessmentFindingAnalyticsResultOutput() GetSecurityAssessmentFindingAnalyticsResultOutput {
	return o
}

func (o GetSecurityAssessmentFindingAnalyticsResultOutput) ToGetSecurityAssessmentFindingAnalyticsResultOutputWithContext(ctx context.Context) GetSecurityAssessmentFindingAnalyticsResultOutput {
	return o
}

func (o GetSecurityAssessmentFindingAnalyticsResultOutput) AccessLevel() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityAssessmentFindingAnalyticsResult) *string { return v.AccessLevel }).(pulumi.StringPtrOutput)
}

func (o GetSecurityAssessmentFindingAnalyticsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityAssessmentFindingAnalyticsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

func (o GetSecurityAssessmentFindingAnalyticsResultOutput) CompartmentIdInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetSecurityAssessmentFindingAnalyticsResult) *bool { return v.CompartmentIdInSubtree }).(pulumi.BoolPtrOutput)
}

func (o GetSecurityAssessmentFindingAnalyticsResultOutput) Filters() GetSecurityAssessmentFindingAnalyticsFilterArrayOutput {
	return o.ApplyT(func(v GetSecurityAssessmentFindingAnalyticsResult) []GetSecurityAssessmentFindingAnalyticsFilter {
		return v.Filters
	}).(GetSecurityAssessmentFindingAnalyticsFilterArrayOutput)
}

// The list of finding_analytics_collection.
func (o GetSecurityAssessmentFindingAnalyticsResultOutput) FindingAnalyticsCollections() GetSecurityAssessmentFindingAnalyticsFindingAnalyticsCollectionArrayOutput {
	return o.ApplyT(func(v GetSecurityAssessmentFindingAnalyticsResult) []GetSecurityAssessmentFindingAnalyticsFindingAnalyticsCollection {
		return v.FindingAnalyticsCollections
	}).(GetSecurityAssessmentFindingAnalyticsFindingAnalyticsCollectionArrayOutput)
}

func (o GetSecurityAssessmentFindingAnalyticsResultOutput) FindingKey() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityAssessmentFindingAnalyticsResult) *string { return v.FindingKey }).(pulumi.StringPtrOutput)
}

func (o GetSecurityAssessmentFindingAnalyticsResultOutput) GroupBy() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityAssessmentFindingAnalyticsResult) *string { return v.GroupBy }).(pulumi.StringPtrOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetSecurityAssessmentFindingAnalyticsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityAssessmentFindingAnalyticsResult) string { return v.Id }).(pulumi.StringOutput)
}

func (o GetSecurityAssessmentFindingAnalyticsResultOutput) IsTopFinding() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetSecurityAssessmentFindingAnalyticsResult) *bool { return v.IsTopFinding }).(pulumi.BoolPtrOutput)
}

// The severity (risk level) of the finding.
func (o GetSecurityAssessmentFindingAnalyticsResultOutput) Severity() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityAssessmentFindingAnalyticsResult) *string { return v.Severity }).(pulumi.StringPtrOutput)
}

// The status of the top finding.  All findings will have "severity" to indicate the risk level, but only top findings will have "status".  Possible status: Pass / Risk (Low, Medium, High)/ Evaluate / Advisory / Deferred Instead of having "Low, Medium, High" in severity, "Risk" will include these three situations in status.
func (o GetSecurityAssessmentFindingAnalyticsResultOutput) TopFindingStatus() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityAssessmentFindingAnalyticsResult) *string { return v.TopFindingStatus }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSecurityAssessmentFindingAnalyticsResultOutput{})
}
