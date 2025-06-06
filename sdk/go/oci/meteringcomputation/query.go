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

// This resource provides the Query resource in Oracle Cloud Infrastructure Metering Computation service.
//
// Returns the created query.
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
//			_, err := meteringcomputation.NewQuery(ctx, "test_query", &meteringcomputation.QueryArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				QueryDefinition: &meteringcomputation.QueryQueryDefinitionArgs{
//					CostAnalysisUi: &meteringcomputation.QueryQueryDefinitionCostAnalysisUiArgs{
//						Graph:             pulumi.Any(queryQueryDefinitionCostAnalysisUiGraph),
//						IsCumulativeGraph: pulumi.Any(queryQueryDefinitionCostAnalysisUiIsCumulativeGraph),
//					},
//					DisplayName: pulumi.Any(queryQueryDefinitionDisplayName),
//					ReportQuery: &meteringcomputation.QueryQueryDefinitionReportQueryArgs{
//						Granularity:      pulumi.Any(queryQueryDefinitionReportQueryGranularity),
//						TenantId:         pulumi.Any(testTenant.Id),
//						CompartmentDepth: pulumi.Any(queryQueryDefinitionReportQueryCompartmentDepth),
//						DateRangeName:    pulumi.Any(queryQueryDefinitionReportQueryDateRangeName),
//						Filter:           pulumi.Any(queryQueryDefinitionReportQueryFilter),
//						Forecast: &meteringcomputation.QueryQueryDefinitionReportQueryForecastArgs{
//							TimeForecastEnded:   pulumi.Any(queryQueryDefinitionReportQueryForecastTimeForecastEnded),
//							ForecastType:        pulumi.Any(queryQueryDefinitionReportQueryForecastForecastType),
//							TimeForecastStarted: pulumi.Any(queryQueryDefinitionReportQueryForecastTimeForecastStarted),
//						},
//						GroupBies: pulumi.Any(queryQueryDefinitionReportQueryGroupBy),
//						GroupByTags: meteringcomputation.QueryQueryDefinitionReportQueryGroupByTagArray{
//							&meteringcomputation.QueryQueryDefinitionReportQueryGroupByTagArgs{
//								Key:       pulumi.Any(queryQueryDefinitionReportQueryGroupByTagKey),
//								Namespace: pulumi.Any(queryQueryDefinitionReportQueryGroupByTagNamespace),
//								Value:     pulumi.Any(queryQueryDefinitionReportQueryGroupByTagValue),
//							},
//						},
//						IsAggregateByTime: pulumi.Any(queryQueryDefinitionReportQueryIsAggregateByTime),
//						QueryType:         pulumi.Any(queryQueryDefinitionReportQueryQueryType),
//						TimeUsageEnded:    pulumi.Any(queryQueryDefinitionReportQueryTimeUsageEnded),
//						TimeUsageStarted:  pulumi.Any(queryQueryDefinitionReportQueryTimeUsageStarted),
//					},
//					Version: pulumi.Any(queryQueryDefinitionVersion),
//				},
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
// Queries can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:MeteringComputation/query:Query test_query "id"
// ```
type Query struct {
	pulumi.CustomResourceState

	// The compartment OCID.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) The common fields for queries.
	QueryDefinition QueryQueryDefinitionOutput `pulumi:"queryDefinition"`
}

// NewQuery registers a new resource with the given unique name, arguments, and options.
func NewQuery(ctx *pulumi.Context,
	name string, args *QueryArgs, opts ...pulumi.ResourceOption) (*Query, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.QueryDefinition == nil {
		return nil, errors.New("invalid value for required argument 'QueryDefinition'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource Query
	err := ctx.RegisterResource("oci:MeteringComputation/query:Query", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetQuery gets an existing Query resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetQuery(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *QueryState, opts ...pulumi.ResourceOption) (*Query, error) {
	var resource Query
	err := ctx.ReadResource("oci:MeteringComputation/query:Query", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering Query resources.
type queryState struct {
	// The compartment OCID.
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) The common fields for queries.
	QueryDefinition *QueryQueryDefinition `pulumi:"queryDefinition"`
}

type QueryState struct {
	// The compartment OCID.
	CompartmentId pulumi.StringPtrInput
	// (Updatable) The common fields for queries.
	QueryDefinition QueryQueryDefinitionPtrInput
}

func (QueryState) ElementType() reflect.Type {
	return reflect.TypeOf((*queryState)(nil)).Elem()
}

type queryArgs struct {
	// The compartment OCID.
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) The common fields for queries.
	QueryDefinition QueryQueryDefinition `pulumi:"queryDefinition"`
}

// The set of arguments for constructing a Query resource.
type QueryArgs struct {
	// The compartment OCID.
	CompartmentId pulumi.StringInput
	// (Updatable) The common fields for queries.
	QueryDefinition QueryQueryDefinitionInput
}

func (QueryArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*queryArgs)(nil)).Elem()
}

type QueryInput interface {
	pulumi.Input

	ToQueryOutput() QueryOutput
	ToQueryOutputWithContext(ctx context.Context) QueryOutput
}

func (*Query) ElementType() reflect.Type {
	return reflect.TypeOf((**Query)(nil)).Elem()
}

func (i *Query) ToQueryOutput() QueryOutput {
	return i.ToQueryOutputWithContext(context.Background())
}

func (i *Query) ToQueryOutputWithContext(ctx context.Context) QueryOutput {
	return pulumi.ToOutputWithContext(ctx, i).(QueryOutput)
}

// QueryArrayInput is an input type that accepts QueryArray and QueryArrayOutput values.
// You can construct a concrete instance of `QueryArrayInput` via:
//
//	QueryArray{ QueryArgs{...} }
type QueryArrayInput interface {
	pulumi.Input

	ToQueryArrayOutput() QueryArrayOutput
	ToQueryArrayOutputWithContext(context.Context) QueryArrayOutput
}

type QueryArray []QueryInput

func (QueryArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Query)(nil)).Elem()
}

func (i QueryArray) ToQueryArrayOutput() QueryArrayOutput {
	return i.ToQueryArrayOutputWithContext(context.Background())
}

func (i QueryArray) ToQueryArrayOutputWithContext(ctx context.Context) QueryArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(QueryArrayOutput)
}

// QueryMapInput is an input type that accepts QueryMap and QueryMapOutput values.
// You can construct a concrete instance of `QueryMapInput` via:
//
//	QueryMap{ "key": QueryArgs{...} }
type QueryMapInput interface {
	pulumi.Input

	ToQueryMapOutput() QueryMapOutput
	ToQueryMapOutputWithContext(context.Context) QueryMapOutput
}

type QueryMap map[string]QueryInput

func (QueryMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Query)(nil)).Elem()
}

func (i QueryMap) ToQueryMapOutput() QueryMapOutput {
	return i.ToQueryMapOutputWithContext(context.Background())
}

func (i QueryMap) ToQueryMapOutputWithContext(ctx context.Context) QueryMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(QueryMapOutput)
}

type QueryOutput struct{ *pulumi.OutputState }

func (QueryOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**Query)(nil)).Elem()
}

func (o QueryOutput) ToQueryOutput() QueryOutput {
	return o
}

func (o QueryOutput) ToQueryOutputWithContext(ctx context.Context) QueryOutput {
	return o
}

// The compartment OCID.
func (o QueryOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *Query) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) The common fields for queries.
func (o QueryOutput) QueryDefinition() QueryQueryDefinitionOutput {
	return o.ApplyT(func(v *Query) QueryQueryDefinitionOutput { return v.QueryDefinition }).(QueryQueryDefinitionOutput)
}

type QueryArrayOutput struct{ *pulumi.OutputState }

func (QueryArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*Query)(nil)).Elem()
}

func (o QueryArrayOutput) ToQueryArrayOutput() QueryArrayOutput {
	return o
}

func (o QueryArrayOutput) ToQueryArrayOutputWithContext(ctx context.Context) QueryArrayOutput {
	return o
}

func (o QueryArrayOutput) Index(i pulumi.IntInput) QueryOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *Query {
		return vs[0].([]*Query)[vs[1].(int)]
	}).(QueryOutput)
}

type QueryMapOutput struct{ *pulumi.OutputState }

func (QueryMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*Query)(nil)).Elem()
}

func (o QueryMapOutput) ToQueryMapOutput() QueryMapOutput {
	return o
}

func (o QueryMapOutput) ToQueryMapOutputWithContext(ctx context.Context) QueryMapOutput {
	return o
}

func (o QueryMapOutput) MapIndex(k pulumi.StringInput) QueryOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *Query {
		return vs[0].(map[string]*Query)[vs[1].(string)]
	}).(QueryOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*QueryInput)(nil)).Elem(), &Query{})
	pulumi.RegisterInputType(reflect.TypeOf((*QueryArrayInput)(nil)).Elem(), QueryArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*QueryMapInput)(nil)).Elem(), QueryMap{})
	pulumi.RegisterOutputType(QueryOutput{})
	pulumi.RegisterOutputType(QueryArrayOutput{})
	pulumi.RegisterOutputType(QueryMapOutput{})
}
