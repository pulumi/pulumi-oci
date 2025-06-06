// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package meteringcomputation

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Usage Carbon Emission resource in Oracle Cloud Infrastructure Metering Computation service.
//
// Returns carbon emission usage for the given account.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/meteringcomputation"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := meteringcomputation.NewUsageCarbonEmission(ctx, "test_usage_carbon_emission", &meteringcomputation.UsageCarbonEmissionArgs{
//				TenantId:                  pulumi.Any(testTenant.Id),
//				TimeUsageEnded:            pulumi.Any(usageCarbonEmissionTimeUsageEnded),
//				TimeUsageStarted:          pulumi.Any(usageCarbonEmissionTimeUsageStarted),
//				CompartmentDepth:          pulumi.Any(usageCarbonEmissionCompartmentDepth),
//				EmissionCalculationMethod: pulumi.Any(usageCarbonEmissionEmissionCalculationMethod),
//				EmissionType:              pulumi.Any(usageCarbonEmissionEmissionType),
//				Granularity:               pulumi.Any(usageCarbonEmissionGranularity),
//				GroupBies:                 pulumi.Any(usageCarbonEmissionGroupBy),
//				GroupByTags: meteringcomputation.UsageCarbonEmissionGroupByTagArray{
//					&meteringcomputation.UsageCarbonEmissionGroupByTagArgs{
//						Key:       pulumi.Any(usageCarbonEmissionGroupByTagKey),
//						Namespace: pulumi.Any(usageCarbonEmissionGroupByTagNamespace),
//						Value:     pulumi.Any(usageCarbonEmissionGroupByTagValue),
//					},
//				},
//				IsAggregateByTime:         pulumi.Any(usageCarbonEmissionIsAggregateByTime),
//				UsageCarbonEmissionFilter: pulumi.Any(usageCarbonEmissionUsageCarbonEmissionFilter),
//			})
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
//
// ## Import
//
// UsageCarbonEmissions can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:MeteringComputation/usageCarbonEmission:UsageCarbonEmission test_usage_carbon_emission "id"
// ```
type UsageCarbonEmission struct {
	pulumi.CustomResourceState

	// The compartment depth level.
	CompartmentDepth pulumi.IntOutput `pulumi:"compartmentDepth"`
	// Specifies the method used for emission calculation, such as POWER_BASED or SPEND_BASED
	EmissionCalculationMethod pulumi.StringOutput `pulumi:"emissionCalculationMethod"`
	// Specifies the type of emission, such as MARKET_BASED or LOCATION_BASED.
	EmissionType pulumi.StringOutput `pulumi:"emissionType"`
	// The carbon emission granularity. DAILY - Daily data aggregation. MONTHLY - Monthly data aggregation.
	Granularity pulumi.StringOutput `pulumi:"granularity"`
	// Aggregate the result by. For example: `["tagNamespace", "tagKey", "tagValue", "service", "skuName", "skuPartNumber", "unit", "compartmentName", "compartmentPath", "compartmentId", "platform", "region", "logicalAd", "resourceId", "resourceName", "tenantId", "tenantName", "subscriptionId"]`
	GroupBies pulumi.StringArrayOutput `pulumi:"groupBies"`
	// GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only supports one tag in the list. For example: `[{"namespace":"oracle", "key":"createdBy"]`
	GroupByTags UsageCarbonEmissionGroupByTagArrayOutput `pulumi:"groupByTags"`
	// Specifies whether aggregated by time. If isAggregateByTime is true, all carbon emissions usage over the query time period are summed.
	IsAggregateByTime pulumi.BoolOutput `pulumi:"isAggregateByTime"`
	// A list of carbon emission usage items.
	Items UsageCarbonEmissionItemArrayOutput `pulumi:"items"`
	// Tenant ID.
	TenantId pulumi.StringOutput `pulumi:"tenantId"`
	// The usage end time.
	TimeUsageEnded pulumi.StringOutput `pulumi:"timeUsageEnded"`
	// The usage start time.
	TimeUsageStarted pulumi.StringOutput `pulumi:"timeUsageStarted"`
	// The filter object for query usage.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	UsageCarbonEmissionFilter pulumi.StringOutput `pulumi:"usageCarbonEmissionFilter"`
}

// NewUsageCarbonEmission registers a new resource with the given unique name, arguments, and options.
func NewUsageCarbonEmission(ctx *pulumi.Context,
	name string, args *UsageCarbonEmissionArgs, opts ...pulumi.ResourceOption) (*UsageCarbonEmission, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.TenantId == nil {
		return nil, errors.New("invalid value for required argument 'TenantId'")
	}
	if args.TimeUsageEnded == nil {
		return nil, errors.New("invalid value for required argument 'TimeUsageEnded'")
	}
	if args.TimeUsageStarted == nil {
		return nil, errors.New("invalid value for required argument 'TimeUsageStarted'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource UsageCarbonEmission
	err := ctx.RegisterResource("oci:MeteringComputation/usageCarbonEmission:UsageCarbonEmission", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetUsageCarbonEmission gets an existing UsageCarbonEmission resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetUsageCarbonEmission(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *UsageCarbonEmissionState, opts ...pulumi.ResourceOption) (*UsageCarbonEmission, error) {
	var resource UsageCarbonEmission
	err := ctx.ReadResource("oci:MeteringComputation/usageCarbonEmission:UsageCarbonEmission", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering UsageCarbonEmission resources.
type usageCarbonEmissionState struct {
	// The compartment depth level.
	CompartmentDepth *int `pulumi:"compartmentDepth"`
	// Specifies the method used for emission calculation, such as POWER_BASED or SPEND_BASED
	EmissionCalculationMethod *string `pulumi:"emissionCalculationMethod"`
	// Specifies the type of emission, such as MARKET_BASED or LOCATION_BASED.
	EmissionType *string `pulumi:"emissionType"`
	// The carbon emission granularity. DAILY - Daily data aggregation. MONTHLY - Monthly data aggregation.
	Granularity *string `pulumi:"granularity"`
	// Aggregate the result by. For example: `["tagNamespace", "tagKey", "tagValue", "service", "skuName", "skuPartNumber", "unit", "compartmentName", "compartmentPath", "compartmentId", "platform", "region", "logicalAd", "resourceId", "resourceName", "tenantId", "tenantName", "subscriptionId"]`
	GroupBies []string `pulumi:"groupBies"`
	// GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only supports one tag in the list. For example: `[{"namespace":"oracle", "key":"createdBy"]`
	GroupByTags []UsageCarbonEmissionGroupByTag `pulumi:"groupByTags"`
	// Specifies whether aggregated by time. If isAggregateByTime is true, all carbon emissions usage over the query time period are summed.
	IsAggregateByTime *bool `pulumi:"isAggregateByTime"`
	// A list of carbon emission usage items.
	Items []UsageCarbonEmissionItem `pulumi:"items"`
	// Tenant ID.
	TenantId *string `pulumi:"tenantId"`
	// The usage end time.
	TimeUsageEnded *string `pulumi:"timeUsageEnded"`
	// The usage start time.
	TimeUsageStarted *string `pulumi:"timeUsageStarted"`
	// The filter object for query usage.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	UsageCarbonEmissionFilter *string `pulumi:"usageCarbonEmissionFilter"`
}

type UsageCarbonEmissionState struct {
	// The compartment depth level.
	CompartmentDepth pulumi.IntPtrInput
	// Specifies the method used for emission calculation, such as POWER_BASED or SPEND_BASED
	EmissionCalculationMethod pulumi.StringPtrInput
	// Specifies the type of emission, such as MARKET_BASED or LOCATION_BASED.
	EmissionType pulumi.StringPtrInput
	// The carbon emission granularity. DAILY - Daily data aggregation. MONTHLY - Monthly data aggregation.
	Granularity pulumi.StringPtrInput
	// Aggregate the result by. For example: `["tagNamespace", "tagKey", "tagValue", "service", "skuName", "skuPartNumber", "unit", "compartmentName", "compartmentPath", "compartmentId", "platform", "region", "logicalAd", "resourceId", "resourceName", "tenantId", "tenantName", "subscriptionId"]`
	GroupBies pulumi.StringArrayInput
	// GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only supports one tag in the list. For example: `[{"namespace":"oracle", "key":"createdBy"]`
	GroupByTags UsageCarbonEmissionGroupByTagArrayInput
	// Specifies whether aggregated by time. If isAggregateByTime is true, all carbon emissions usage over the query time period are summed.
	IsAggregateByTime pulumi.BoolPtrInput
	// A list of carbon emission usage items.
	Items UsageCarbonEmissionItemArrayInput
	// Tenant ID.
	TenantId pulumi.StringPtrInput
	// The usage end time.
	TimeUsageEnded pulumi.StringPtrInput
	// The usage start time.
	TimeUsageStarted pulumi.StringPtrInput
	// The filter object for query usage.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	UsageCarbonEmissionFilter pulumi.StringPtrInput
}

func (UsageCarbonEmissionState) ElementType() reflect.Type {
	return reflect.TypeOf((*usageCarbonEmissionState)(nil)).Elem()
}

type usageCarbonEmissionArgs struct {
	// The compartment depth level.
	CompartmentDepth *int `pulumi:"compartmentDepth"`
	// Specifies the method used for emission calculation, such as POWER_BASED or SPEND_BASED
	EmissionCalculationMethod *string `pulumi:"emissionCalculationMethod"`
	// Specifies the type of emission, such as MARKET_BASED or LOCATION_BASED.
	EmissionType *string `pulumi:"emissionType"`
	// The carbon emission granularity. DAILY - Daily data aggregation. MONTHLY - Monthly data aggregation.
	Granularity *string `pulumi:"granularity"`
	// Aggregate the result by. For example: `["tagNamespace", "tagKey", "tagValue", "service", "skuName", "skuPartNumber", "unit", "compartmentName", "compartmentPath", "compartmentId", "platform", "region", "logicalAd", "resourceId", "resourceName", "tenantId", "tenantName", "subscriptionId"]`
	GroupBies []string `pulumi:"groupBies"`
	// GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only supports one tag in the list. For example: `[{"namespace":"oracle", "key":"createdBy"]`
	GroupByTags []UsageCarbonEmissionGroupByTag `pulumi:"groupByTags"`
	// Specifies whether aggregated by time. If isAggregateByTime is true, all carbon emissions usage over the query time period are summed.
	IsAggregateByTime *bool `pulumi:"isAggregateByTime"`
	// Tenant ID.
	TenantId string `pulumi:"tenantId"`
	// The usage end time.
	TimeUsageEnded string `pulumi:"timeUsageEnded"`
	// The usage start time.
	TimeUsageStarted string `pulumi:"timeUsageStarted"`
	// The filter object for query usage.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	UsageCarbonEmissionFilter *string `pulumi:"usageCarbonEmissionFilter"`
}

// The set of arguments for constructing a UsageCarbonEmission resource.
type UsageCarbonEmissionArgs struct {
	// The compartment depth level.
	CompartmentDepth pulumi.IntPtrInput
	// Specifies the method used for emission calculation, such as POWER_BASED or SPEND_BASED
	EmissionCalculationMethod pulumi.StringPtrInput
	// Specifies the type of emission, such as MARKET_BASED or LOCATION_BASED.
	EmissionType pulumi.StringPtrInput
	// The carbon emission granularity. DAILY - Daily data aggregation. MONTHLY - Monthly data aggregation.
	Granularity pulumi.StringPtrInput
	// Aggregate the result by. For example: `["tagNamespace", "tagKey", "tagValue", "service", "skuName", "skuPartNumber", "unit", "compartmentName", "compartmentPath", "compartmentId", "platform", "region", "logicalAd", "resourceId", "resourceName", "tenantId", "tenantName", "subscriptionId"]`
	GroupBies pulumi.StringArrayInput
	// GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only supports one tag in the list. For example: `[{"namespace":"oracle", "key":"createdBy"]`
	GroupByTags UsageCarbonEmissionGroupByTagArrayInput
	// Specifies whether aggregated by time. If isAggregateByTime is true, all carbon emissions usage over the query time period are summed.
	IsAggregateByTime pulumi.BoolPtrInput
	// Tenant ID.
	TenantId pulumi.StringInput
	// The usage end time.
	TimeUsageEnded pulumi.StringInput
	// The usage start time.
	TimeUsageStarted pulumi.StringInput
	// The filter object for query usage.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	UsageCarbonEmissionFilter pulumi.StringPtrInput
}

func (UsageCarbonEmissionArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*usageCarbonEmissionArgs)(nil)).Elem()
}

type UsageCarbonEmissionInput interface {
	pulumi.Input

	ToUsageCarbonEmissionOutput() UsageCarbonEmissionOutput
	ToUsageCarbonEmissionOutputWithContext(ctx context.Context) UsageCarbonEmissionOutput
}

func (*UsageCarbonEmission) ElementType() reflect.Type {
	return reflect.TypeOf((**UsageCarbonEmission)(nil)).Elem()
}

func (i *UsageCarbonEmission) ToUsageCarbonEmissionOutput() UsageCarbonEmissionOutput {
	return i.ToUsageCarbonEmissionOutputWithContext(context.Background())
}

func (i *UsageCarbonEmission) ToUsageCarbonEmissionOutputWithContext(ctx context.Context) UsageCarbonEmissionOutput {
	return pulumi.ToOutputWithContext(ctx, i).(UsageCarbonEmissionOutput)
}

// UsageCarbonEmissionArrayInput is an input type that accepts UsageCarbonEmissionArray and UsageCarbonEmissionArrayOutput values.
// You can construct a concrete instance of `UsageCarbonEmissionArrayInput` via:
//
//	UsageCarbonEmissionArray{ UsageCarbonEmissionArgs{...} }
type UsageCarbonEmissionArrayInput interface {
	pulumi.Input

	ToUsageCarbonEmissionArrayOutput() UsageCarbonEmissionArrayOutput
	ToUsageCarbonEmissionArrayOutputWithContext(context.Context) UsageCarbonEmissionArrayOutput
}

type UsageCarbonEmissionArray []UsageCarbonEmissionInput

func (UsageCarbonEmissionArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*UsageCarbonEmission)(nil)).Elem()
}

func (i UsageCarbonEmissionArray) ToUsageCarbonEmissionArrayOutput() UsageCarbonEmissionArrayOutput {
	return i.ToUsageCarbonEmissionArrayOutputWithContext(context.Background())
}

func (i UsageCarbonEmissionArray) ToUsageCarbonEmissionArrayOutputWithContext(ctx context.Context) UsageCarbonEmissionArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(UsageCarbonEmissionArrayOutput)
}

// UsageCarbonEmissionMapInput is an input type that accepts UsageCarbonEmissionMap and UsageCarbonEmissionMapOutput values.
// You can construct a concrete instance of `UsageCarbonEmissionMapInput` via:
//
//	UsageCarbonEmissionMap{ "key": UsageCarbonEmissionArgs{...} }
type UsageCarbonEmissionMapInput interface {
	pulumi.Input

	ToUsageCarbonEmissionMapOutput() UsageCarbonEmissionMapOutput
	ToUsageCarbonEmissionMapOutputWithContext(context.Context) UsageCarbonEmissionMapOutput
}

type UsageCarbonEmissionMap map[string]UsageCarbonEmissionInput

func (UsageCarbonEmissionMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*UsageCarbonEmission)(nil)).Elem()
}

func (i UsageCarbonEmissionMap) ToUsageCarbonEmissionMapOutput() UsageCarbonEmissionMapOutput {
	return i.ToUsageCarbonEmissionMapOutputWithContext(context.Background())
}

func (i UsageCarbonEmissionMap) ToUsageCarbonEmissionMapOutputWithContext(ctx context.Context) UsageCarbonEmissionMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(UsageCarbonEmissionMapOutput)
}

type UsageCarbonEmissionOutput struct{ *pulumi.OutputState }

func (UsageCarbonEmissionOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**UsageCarbonEmission)(nil)).Elem()
}

func (o UsageCarbonEmissionOutput) ToUsageCarbonEmissionOutput() UsageCarbonEmissionOutput {
	return o
}

func (o UsageCarbonEmissionOutput) ToUsageCarbonEmissionOutputWithContext(ctx context.Context) UsageCarbonEmissionOutput {
	return o
}

// The compartment depth level.
func (o UsageCarbonEmissionOutput) CompartmentDepth() pulumi.IntOutput {
	return o.ApplyT(func(v *UsageCarbonEmission) pulumi.IntOutput { return v.CompartmentDepth }).(pulumi.IntOutput)
}

// Specifies the method used for emission calculation, such as POWER_BASED or SPEND_BASED
func (o UsageCarbonEmissionOutput) EmissionCalculationMethod() pulumi.StringOutput {
	return o.ApplyT(func(v *UsageCarbonEmission) pulumi.StringOutput { return v.EmissionCalculationMethod }).(pulumi.StringOutput)
}

// Specifies the type of emission, such as MARKET_BASED or LOCATION_BASED.
func (o UsageCarbonEmissionOutput) EmissionType() pulumi.StringOutput {
	return o.ApplyT(func(v *UsageCarbonEmission) pulumi.StringOutput { return v.EmissionType }).(pulumi.StringOutput)
}

// The carbon emission granularity. DAILY - Daily data aggregation. MONTHLY - Monthly data aggregation.
func (o UsageCarbonEmissionOutput) Granularity() pulumi.StringOutput {
	return o.ApplyT(func(v *UsageCarbonEmission) pulumi.StringOutput { return v.Granularity }).(pulumi.StringOutput)
}

// Aggregate the result by. For example: `["tagNamespace", "tagKey", "tagValue", "service", "skuName", "skuPartNumber", "unit", "compartmentName", "compartmentPath", "compartmentId", "platform", "region", "logicalAd", "resourceId", "resourceName", "tenantId", "tenantName", "subscriptionId"]`
func (o UsageCarbonEmissionOutput) GroupBies() pulumi.StringArrayOutput {
	return o.ApplyT(func(v *UsageCarbonEmission) pulumi.StringArrayOutput { return v.GroupBies }).(pulumi.StringArrayOutput)
}

// GroupBy a specific tagKey. Provide the tagNamespace and tagKey in the tag object. Only supports one tag in the list. For example: `[{"namespace":"oracle", "key":"createdBy"]`
func (o UsageCarbonEmissionOutput) GroupByTags() UsageCarbonEmissionGroupByTagArrayOutput {
	return o.ApplyT(func(v *UsageCarbonEmission) UsageCarbonEmissionGroupByTagArrayOutput { return v.GroupByTags }).(UsageCarbonEmissionGroupByTagArrayOutput)
}

// Specifies whether aggregated by time. If isAggregateByTime is true, all carbon emissions usage over the query time period are summed.
func (o UsageCarbonEmissionOutput) IsAggregateByTime() pulumi.BoolOutput {
	return o.ApplyT(func(v *UsageCarbonEmission) pulumi.BoolOutput { return v.IsAggregateByTime }).(pulumi.BoolOutput)
}

// A list of carbon emission usage items.
func (o UsageCarbonEmissionOutput) Items() UsageCarbonEmissionItemArrayOutput {
	return o.ApplyT(func(v *UsageCarbonEmission) UsageCarbonEmissionItemArrayOutput { return v.Items }).(UsageCarbonEmissionItemArrayOutput)
}

// Tenant ID.
func (o UsageCarbonEmissionOutput) TenantId() pulumi.StringOutput {
	return o.ApplyT(func(v *UsageCarbonEmission) pulumi.StringOutput { return v.TenantId }).(pulumi.StringOutput)
}

// The usage end time.
func (o UsageCarbonEmissionOutput) TimeUsageEnded() pulumi.StringOutput {
	return o.ApplyT(func(v *UsageCarbonEmission) pulumi.StringOutput { return v.TimeUsageEnded }).(pulumi.StringOutput)
}

// The usage start time.
func (o UsageCarbonEmissionOutput) TimeUsageStarted() pulumi.StringOutput {
	return o.ApplyT(func(v *UsageCarbonEmission) pulumi.StringOutput { return v.TimeUsageStarted }).(pulumi.StringOutput)
}

// The filter object for query usage.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o UsageCarbonEmissionOutput) UsageCarbonEmissionFilter() pulumi.StringOutput {
	return o.ApplyT(func(v *UsageCarbonEmission) pulumi.StringOutput { return v.UsageCarbonEmissionFilter }).(pulumi.StringOutput)
}

type UsageCarbonEmissionArrayOutput struct{ *pulumi.OutputState }

func (UsageCarbonEmissionArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*UsageCarbonEmission)(nil)).Elem()
}

func (o UsageCarbonEmissionArrayOutput) ToUsageCarbonEmissionArrayOutput() UsageCarbonEmissionArrayOutput {
	return o
}

func (o UsageCarbonEmissionArrayOutput) ToUsageCarbonEmissionArrayOutputWithContext(ctx context.Context) UsageCarbonEmissionArrayOutput {
	return o
}

func (o UsageCarbonEmissionArrayOutput) Index(i pulumi.IntInput) UsageCarbonEmissionOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *UsageCarbonEmission {
		return vs[0].([]*UsageCarbonEmission)[vs[1].(int)]
	}).(UsageCarbonEmissionOutput)
}

type UsageCarbonEmissionMapOutput struct{ *pulumi.OutputState }

func (UsageCarbonEmissionMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*UsageCarbonEmission)(nil)).Elem()
}

func (o UsageCarbonEmissionMapOutput) ToUsageCarbonEmissionMapOutput() UsageCarbonEmissionMapOutput {
	return o
}

func (o UsageCarbonEmissionMapOutput) ToUsageCarbonEmissionMapOutputWithContext(ctx context.Context) UsageCarbonEmissionMapOutput {
	return o
}

func (o UsageCarbonEmissionMapOutput) MapIndex(k pulumi.StringInput) UsageCarbonEmissionOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *UsageCarbonEmission {
		return vs[0].(map[string]*UsageCarbonEmission)[vs[1].(string)]
	}).(UsageCarbonEmissionOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*UsageCarbonEmissionInput)(nil)).Elem(), &UsageCarbonEmission{})
	pulumi.RegisterInputType(reflect.TypeOf((*UsageCarbonEmissionArrayInput)(nil)).Elem(), UsageCarbonEmissionArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*UsageCarbonEmissionMapInput)(nil)).Elem(), UsageCarbonEmissionMap{})
	pulumi.RegisterOutputType(UsageCarbonEmissionOutput{})
	pulumi.RegisterOutputType(UsageCarbonEmissionArrayOutput{})
	pulumi.RegisterOutputType(UsageCarbonEmissionMapOutput{})
}
