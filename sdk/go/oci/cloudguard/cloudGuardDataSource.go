// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudguard

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Data Source resource in Oracle Cloud Infrastructure Cloud Guard service.
//
// Creates a data source (DataSource resource), using parameters passed
// through a CreateDataSourceDetails resource.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/cloudguard"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := cloudguard.NewCloudGuardDataSource(ctx, "test_data_source", &cloudguard.CloudGuardDataSourceArgs{
//				CompartmentId:          pulumi.Any(compartmentId),
//				DataSourceFeedProvider: pulumi.Any(dataSourceDataSourceFeedProvider),
//				DisplayName:            pulumi.Any(dataSourceDisplayName),
//				DataSourceDetails: &cloudguard.CloudGuardDataSourceDataSourceDetailsArgs{
//					DataSourceFeedProvider:  pulumi.Any(dataSourceDataSourceDetailsDataSourceFeedProvider),
//					AdditionalEntitiesCount: pulumi.Any(dataSourceDataSourceDetailsAdditionalEntitiesCount),
//					Description:             pulumi.Any(dataSourceDataSourceDetailsDescription),
//					IntervalInMinutes:       pulumi.Any(dataSourceDataSourceDetailsIntervalInMinutes),
//					IntervalInSeconds:       pulumi.Any(dataSourceDataSourceDetailsIntervalInSeconds),
//					LoggingQueryDetails: &cloudguard.CloudGuardDataSourceDataSourceDetailsLoggingQueryDetailsArgs{
//						LoggingQueryType: pulumi.Any(dataSourceDataSourceDetailsLoggingQueryDetailsLoggingQueryType),
//						KeyEntitiesCount: pulumi.Any(dataSourceDataSourceDetailsLoggingQueryDetailsKeyEntitiesCount),
//					},
//					LoggingQueryType: pulumi.Any(dataSourceDataSourceDetailsLoggingQueryType),
//					Operator:         pulumi.Any(dataSourceDataSourceDetailsOperator),
//					Query:            pulumi.Any(dataSourceDataSourceDetailsQuery),
//					QueryStartTime: &cloudguard.CloudGuardDataSourceDataSourceDetailsQueryStartTimeArgs{
//						StartPolicyType: pulumi.Any(dataSourceDataSourceDetailsQueryStartTimeStartPolicyType),
//						QueryStartTime:  pulumi.Any(dataSourceDataSourceDetailsQueryStartTimeQueryStartTime),
//					},
//					Regions: pulumi.Any(dataSourceDataSourceDetailsRegions),
//					ScheduledQueryScopeDetails: cloudguard.CloudGuardDataSourceDataSourceDetailsScheduledQueryScopeDetailArray{
//						&cloudguard.CloudGuardDataSourceDataSourceDetailsScheduledQueryScopeDetailArgs{
//							Region:       pulumi.Any(dataSourceDataSourceDetailsScheduledQueryScopeDetailsRegion),
//							ResourceIds:  pulumi.Any(dataSourceDataSourceDetailsScheduledQueryScopeDetailsResourceIds),
//							ResourceType: pulumi.Any(dataSourceDataSourceDetailsScheduledQueryScopeDetailsResourceType),
//						},
//					},
//					Threshold: pulumi.Any(dataSourceDataSourceDetailsThreshold),
//				},
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//				Status: pulumi.Any(dataSourceStatus),
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
// DataSources can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:CloudGuard/cloudGuardDataSource:CloudGuardDataSource test_data_source "id"
// ```
type CloudGuardDataSource struct {
	pulumi.CustomResourceState

	// (Updatable) Compartment OCID of the data source
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// (Updatable) Details specific to the data source type.
	DataSourceDetails CloudGuardDataSourceDataSourceDetailsOutput `pulumi:"dataSourceDetails"`
	// Information about the detector recipe and rule attached
	DataSourceDetectorMappingInfos CloudGuardDataSourceDataSourceDetectorMappingInfoArrayOutput `pulumi:"dataSourceDetectorMappingInfos"`
	// Type of data source feed provider (LoggingQuery)
	DataSourceFeedProvider pulumi.StringOutput `pulumi:"dataSourceFeedProvider"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) Data source display name
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// Information about the region and status of query replication
	RegionStatusDetails CloudGuardDataSourceRegionStatusDetailArrayOutput `pulumi:"regionStatusDetails"`
	// The current lifecycle state of the resource.
	State pulumi.StringOutput `pulumi:"state"`
	// (Updatable) Enablement status of data source.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Status pulumi.StringOutput `pulumi:"status"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The date and time the Data source was created. Format defined by RFC3339.
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The date and time the data source was updated. Format defined by RFC3339.
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewCloudGuardDataSource registers a new resource with the given unique name, arguments, and options.
func NewCloudGuardDataSource(ctx *pulumi.Context,
	name string, args *CloudGuardDataSourceArgs, opts ...pulumi.ResourceOption) (*CloudGuardDataSource, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DataSourceFeedProvider == nil {
		return nil, errors.New("invalid value for required argument 'DataSourceFeedProvider'")
	}
	if args.DisplayName == nil {
		return nil, errors.New("invalid value for required argument 'DisplayName'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource CloudGuardDataSource
	err := ctx.RegisterResource("oci:CloudGuard/cloudGuardDataSource:CloudGuardDataSource", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetCloudGuardDataSource gets an existing CloudGuardDataSource resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetCloudGuardDataSource(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *CloudGuardDataSourceState, opts ...pulumi.ResourceOption) (*CloudGuardDataSource, error) {
	var resource CloudGuardDataSource
	err := ctx.ReadResource("oci:CloudGuard/cloudGuardDataSource:CloudGuardDataSource", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering CloudGuardDataSource resources.
type cloudGuardDataSourceState struct {
	// (Updatable) Compartment OCID of the data source
	CompartmentId *string `pulumi:"compartmentId"`
	// (Updatable) Details specific to the data source type.
	DataSourceDetails *CloudGuardDataSourceDataSourceDetails `pulumi:"dataSourceDetails"`
	// Information about the detector recipe and rule attached
	DataSourceDetectorMappingInfos []CloudGuardDataSourceDataSourceDetectorMappingInfo `pulumi:"dataSourceDetectorMappingInfos"`
	// Type of data source feed provider (LoggingQuery)
	DataSourceFeedProvider *string `pulumi:"dataSourceFeedProvider"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Data source display name
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// Information about the region and status of query replication
	RegionStatusDetails []CloudGuardDataSourceRegionStatusDetail `pulumi:"regionStatusDetails"`
	// The current lifecycle state of the resource.
	State *string `pulumi:"state"`
	// (Updatable) Enablement status of data source.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Status *string `pulumi:"status"`
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The date and time the Data source was created. Format defined by RFC3339.
	TimeCreated *string `pulumi:"timeCreated"`
	// The date and time the data source was updated. Format defined by RFC3339.
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type CloudGuardDataSourceState struct {
	// (Updatable) Compartment OCID of the data source
	CompartmentId pulumi.StringPtrInput
	// (Updatable) Details specific to the data source type.
	DataSourceDetails CloudGuardDataSourceDataSourceDetailsPtrInput
	// Information about the detector recipe and rule attached
	DataSourceDetectorMappingInfos CloudGuardDataSourceDataSourceDetectorMappingInfoArrayInput
	// Type of data source feed provider (LoggingQuery)
	DataSourceFeedProvider pulumi.StringPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Data source display name
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags pulumi.StringMapInput
	// Information about the region and status of query replication
	RegionStatusDetails CloudGuardDataSourceRegionStatusDetailArrayInput
	// The current lifecycle state of the resource.
	State pulumi.StringPtrInput
	// (Updatable) Enablement status of data source.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Status pulumi.StringPtrInput
	// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The date and time the Data source was created. Format defined by RFC3339.
	TimeCreated pulumi.StringPtrInput
	// The date and time the data source was updated. Format defined by RFC3339.
	TimeUpdated pulumi.StringPtrInput
}

func (CloudGuardDataSourceState) ElementType() reflect.Type {
	return reflect.TypeOf((*cloudGuardDataSourceState)(nil)).Elem()
}

type cloudGuardDataSourceArgs struct {
	// (Updatable) Compartment OCID of the data source
	CompartmentId string `pulumi:"compartmentId"`
	// (Updatable) Details specific to the data source type.
	DataSourceDetails *CloudGuardDataSourceDataSourceDetails `pulumi:"dataSourceDetails"`
	// Type of data source feed provider (LoggingQuery)
	DataSourceFeedProvider string `pulumi:"dataSourceFeedProvider"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) Data source display name
	DisplayName string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// (Updatable) Enablement status of data source.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Status *string `pulumi:"status"`
}

// The set of arguments for constructing a CloudGuardDataSource resource.
type CloudGuardDataSourceArgs struct {
	// (Updatable) Compartment OCID of the data source
	CompartmentId pulumi.StringInput
	// (Updatable) Details specific to the data source type.
	DataSourceDetails CloudGuardDataSourceDataSourceDetailsPtrInput
	// Type of data source feed provider (LoggingQuery)
	DataSourceFeedProvider pulumi.StringInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) Data source display name
	DisplayName pulumi.StringInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	//
	// Avoid entering confidential information.
	FreeformTags pulumi.StringMapInput
	// (Updatable) Enablement status of data source.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	Status pulumi.StringPtrInput
}

func (CloudGuardDataSourceArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*cloudGuardDataSourceArgs)(nil)).Elem()
}

type CloudGuardDataSourceInput interface {
	pulumi.Input

	ToCloudGuardDataSourceOutput() CloudGuardDataSourceOutput
	ToCloudGuardDataSourceOutputWithContext(ctx context.Context) CloudGuardDataSourceOutput
}

func (*CloudGuardDataSource) ElementType() reflect.Type {
	return reflect.TypeOf((**CloudGuardDataSource)(nil)).Elem()
}

func (i *CloudGuardDataSource) ToCloudGuardDataSourceOutput() CloudGuardDataSourceOutput {
	return i.ToCloudGuardDataSourceOutputWithContext(context.Background())
}

func (i *CloudGuardDataSource) ToCloudGuardDataSourceOutputWithContext(ctx context.Context) CloudGuardDataSourceOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardDataSourceOutput)
}

// CloudGuardDataSourceArrayInput is an input type that accepts CloudGuardDataSourceArray and CloudGuardDataSourceArrayOutput values.
// You can construct a concrete instance of `CloudGuardDataSourceArrayInput` via:
//
//	CloudGuardDataSourceArray{ CloudGuardDataSourceArgs{...} }
type CloudGuardDataSourceArrayInput interface {
	pulumi.Input

	ToCloudGuardDataSourceArrayOutput() CloudGuardDataSourceArrayOutput
	ToCloudGuardDataSourceArrayOutputWithContext(context.Context) CloudGuardDataSourceArrayOutput
}

type CloudGuardDataSourceArray []CloudGuardDataSourceInput

func (CloudGuardDataSourceArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CloudGuardDataSource)(nil)).Elem()
}

func (i CloudGuardDataSourceArray) ToCloudGuardDataSourceArrayOutput() CloudGuardDataSourceArrayOutput {
	return i.ToCloudGuardDataSourceArrayOutputWithContext(context.Background())
}

func (i CloudGuardDataSourceArray) ToCloudGuardDataSourceArrayOutputWithContext(ctx context.Context) CloudGuardDataSourceArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardDataSourceArrayOutput)
}

// CloudGuardDataSourceMapInput is an input type that accepts CloudGuardDataSourceMap and CloudGuardDataSourceMapOutput values.
// You can construct a concrete instance of `CloudGuardDataSourceMapInput` via:
//
//	CloudGuardDataSourceMap{ "key": CloudGuardDataSourceArgs{...} }
type CloudGuardDataSourceMapInput interface {
	pulumi.Input

	ToCloudGuardDataSourceMapOutput() CloudGuardDataSourceMapOutput
	ToCloudGuardDataSourceMapOutputWithContext(context.Context) CloudGuardDataSourceMapOutput
}

type CloudGuardDataSourceMap map[string]CloudGuardDataSourceInput

func (CloudGuardDataSourceMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CloudGuardDataSource)(nil)).Elem()
}

func (i CloudGuardDataSourceMap) ToCloudGuardDataSourceMapOutput() CloudGuardDataSourceMapOutput {
	return i.ToCloudGuardDataSourceMapOutputWithContext(context.Background())
}

func (i CloudGuardDataSourceMap) ToCloudGuardDataSourceMapOutputWithContext(ctx context.Context) CloudGuardDataSourceMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(CloudGuardDataSourceMapOutput)
}

type CloudGuardDataSourceOutput struct{ *pulumi.OutputState }

func (CloudGuardDataSourceOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**CloudGuardDataSource)(nil)).Elem()
}

func (o CloudGuardDataSourceOutput) ToCloudGuardDataSourceOutput() CloudGuardDataSourceOutput {
	return o
}

func (o CloudGuardDataSourceOutput) ToCloudGuardDataSourceOutputWithContext(ctx context.Context) CloudGuardDataSourceOutput {
	return o
}

// (Updatable) Compartment OCID of the data source
func (o CloudGuardDataSourceOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *CloudGuardDataSource) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// (Updatable) Details specific to the data source type.
func (o CloudGuardDataSourceOutput) DataSourceDetails() CloudGuardDataSourceDataSourceDetailsOutput {
	return o.ApplyT(func(v *CloudGuardDataSource) CloudGuardDataSourceDataSourceDetailsOutput { return v.DataSourceDetails }).(CloudGuardDataSourceDataSourceDetailsOutput)
}

// Information about the detector recipe and rule attached
func (o CloudGuardDataSourceOutput) DataSourceDetectorMappingInfos() CloudGuardDataSourceDataSourceDetectorMappingInfoArrayOutput {
	return o.ApplyT(func(v *CloudGuardDataSource) CloudGuardDataSourceDataSourceDetectorMappingInfoArrayOutput {
		return v.DataSourceDetectorMappingInfos
	}).(CloudGuardDataSourceDataSourceDetectorMappingInfoArrayOutput)
}

// Type of data source feed provider (LoggingQuery)
func (o CloudGuardDataSourceOutput) DataSourceFeedProvider() pulumi.StringOutput {
	return o.ApplyT(func(v *CloudGuardDataSource) pulumi.StringOutput { return v.DataSourceFeedProvider }).(pulumi.StringOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o CloudGuardDataSourceOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *CloudGuardDataSource) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) Data source display name
func (o CloudGuardDataSourceOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *CloudGuardDataSource) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
//
// Avoid entering confidential information.
func (o CloudGuardDataSourceOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *CloudGuardDataSource) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// Information about the region and status of query replication
func (o CloudGuardDataSourceOutput) RegionStatusDetails() CloudGuardDataSourceRegionStatusDetailArrayOutput {
	return o.ApplyT(func(v *CloudGuardDataSource) CloudGuardDataSourceRegionStatusDetailArrayOutput {
		return v.RegionStatusDetails
	}).(CloudGuardDataSourceRegionStatusDetailArrayOutput)
}

// The current lifecycle state of the resource.
func (o CloudGuardDataSourceOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *CloudGuardDataSource) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// (Updatable) Enablement status of data source.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o CloudGuardDataSourceOutput) Status() pulumi.StringOutput {
	return o.ApplyT(func(v *CloudGuardDataSource) pulumi.StringOutput { return v.Status }).(pulumi.StringOutput)
}

// System tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). System tags can be viewed by users, but can only be created by the system.  Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o CloudGuardDataSourceOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *CloudGuardDataSource) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The date and time the Data source was created. Format defined by RFC3339.
func (o CloudGuardDataSourceOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *CloudGuardDataSource) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The date and time the data source was updated. Format defined by RFC3339.
func (o CloudGuardDataSourceOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *CloudGuardDataSource) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type CloudGuardDataSourceArrayOutput struct{ *pulumi.OutputState }

func (CloudGuardDataSourceArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*CloudGuardDataSource)(nil)).Elem()
}

func (o CloudGuardDataSourceArrayOutput) ToCloudGuardDataSourceArrayOutput() CloudGuardDataSourceArrayOutput {
	return o
}

func (o CloudGuardDataSourceArrayOutput) ToCloudGuardDataSourceArrayOutputWithContext(ctx context.Context) CloudGuardDataSourceArrayOutput {
	return o
}

func (o CloudGuardDataSourceArrayOutput) Index(i pulumi.IntInput) CloudGuardDataSourceOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *CloudGuardDataSource {
		return vs[0].([]*CloudGuardDataSource)[vs[1].(int)]
	}).(CloudGuardDataSourceOutput)
}

type CloudGuardDataSourceMapOutput struct{ *pulumi.OutputState }

func (CloudGuardDataSourceMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*CloudGuardDataSource)(nil)).Elem()
}

func (o CloudGuardDataSourceMapOutput) ToCloudGuardDataSourceMapOutput() CloudGuardDataSourceMapOutput {
	return o
}

func (o CloudGuardDataSourceMapOutput) ToCloudGuardDataSourceMapOutputWithContext(ctx context.Context) CloudGuardDataSourceMapOutput {
	return o
}

func (o CloudGuardDataSourceMapOutput) MapIndex(k pulumi.StringInput) CloudGuardDataSourceOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *CloudGuardDataSource {
		return vs[0].(map[string]*CloudGuardDataSource)[vs[1].(string)]
	}).(CloudGuardDataSourceOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*CloudGuardDataSourceInput)(nil)).Elem(), &CloudGuardDataSource{})
	pulumi.RegisterInputType(reflect.TypeOf((*CloudGuardDataSourceArrayInput)(nil)).Elem(), CloudGuardDataSourceArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*CloudGuardDataSourceMapInput)(nil)).Elem(), CloudGuardDataSourceMap{})
	pulumi.RegisterOutputType(CloudGuardDataSourceOutput{})
	pulumi.RegisterOutputType(CloudGuardDataSourceArrayOutput{})
	pulumi.RegisterOutputType(CloudGuardDataSourceMapOutput{})
}
