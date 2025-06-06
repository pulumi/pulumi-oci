// Code generated by pulumi-language-go DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package aianomalydetection

import (
	"context"
	"reflect"

	"errors"
	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/internal"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This resource provides the Data Asset resource in Oracle Cloud Infrastructure Ai Anomaly Detection service.
//
// Creates a new DataAsset.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/v3/go/oci/aianomalydetection"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := aianomalydetection.NewDataAsset(ctx, "test_data_asset", &aianomalydetection.DataAssetArgs{
//				CompartmentId: pulumi.Any(compartmentId),
//				DataSourceDetails: &aianomalydetection.DataAssetDataSourceDetailsArgs{
//					DataSourceType:         pulumi.Any(dataAssetDataSourceDetailsDataSourceType),
//					AtpPasswordSecretId:    pulumi.Any(testSecret.Id),
//					AtpUserName:            pulumi.Any(testUser.Name),
//					Bucket:                 pulumi.Any(dataAssetDataSourceDetailsBucket),
//					CwalletFileSecretId:    pulumi.Any(testSecret.Id),
//					DatabaseName:           pulumi.Any(testDatabase.Name),
//					EwalletFileSecretId:    pulumi.Any(testSecret.Id),
//					KeyStoreFileSecretId:   pulumi.Any(testSecret.Id),
//					MeasurementName:        pulumi.Any(dataAssetDataSourceDetailsMeasurementName),
//					Namespace:              pulumi.Any(dataAssetDataSourceDetailsNamespace),
//					Object:                 pulumi.Any(dataAssetDataSourceDetailsObject),
//					OjdbcFileSecretId:      pulumi.Any(testSecret.Id),
//					PasswordSecretId:       pulumi.Any(testSecret.Id),
//					TableName:              pulumi.Any(testTable.Name),
//					TnsnamesFileSecretId:   pulumi.Any(testSecret.Id),
//					TruststoreFileSecretId: pulumi.Any(testSecret.Id),
//					Url:                    pulumi.Any(dataAssetDataSourceDetailsUrl),
//					UserName:               pulumi.Any(testUser.Name),
//					VersionSpecificDetails: &aianomalydetection.DataAssetDataSourceDetailsVersionSpecificDetailsArgs{
//						InfluxVersion:       pulumi.Any(dataAssetDataSourceDetailsVersionSpecificDetailsInfluxVersion),
//						Bucket:              pulumi.Any(dataAssetDataSourceDetailsVersionSpecificDetailsBucket),
//						DatabaseName:        pulumi.Any(testDatabase.Name),
//						OrganizationName:    pulumi.Any(dataAssetDataSourceDetailsVersionSpecificDetailsOrganizationName),
//						RetentionPolicyName: pulumi.Any(testPolicy.Name),
//					},
//					WalletPasswordSecretId: pulumi.Any(testSecret.Id),
//				},
//				ProjectId: pulumi.Any(testProject.Id),
//				DefinedTags: pulumi.StringMap{
//					"foo-namespace.bar-key": pulumi.String("value"),
//				},
//				Description: pulumi.Any(dataAssetDescription),
//				DisplayName: pulumi.Any(dataAssetDisplayName),
//				FreeformTags: pulumi.StringMap{
//					"bar-key": pulumi.String("value"),
//				},
//				PrivateEndpointId: pulumi.Any(testPrivateEndpoint.Id),
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
// DataAssets can be imported using the `id`, e.g.
//
// ```sh
// $ pulumi import oci:AiAnomalyDetection/dataAsset:DataAsset test_data_asset "id"
// ```
type DataAsset struct {
	pulumi.CustomResourceState

	// (Updatable) The OCID for the data asset's compartment.
	CompartmentId pulumi.StringOutput `pulumi:"compartmentId"`
	// Possible data sources
	DataSourceDetails DataAssetDataSourceDetailsOutput `pulumi:"dataSourceDetails"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapOutput `pulumi:"definedTags"`
	// (Updatable) A short description of the Ai data asset
	Description pulumi.StringOutput `pulumi:"description"`
	// (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
	DisplayName pulumi.StringOutput `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapOutput `pulumi:"freeformTags"`
	// OCID of Private Endpoint.
	PrivateEndpointId pulumi.StringOutput `pulumi:"privateEndpointId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the data asset.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId pulumi.StringOutput `pulumi:"projectId"`
	// The lifecycle state of the Data Asset.
	State pulumi.StringOutput `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapOutput `pulumi:"systemTags"`
	// The time the the DataAsset was created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringOutput `pulumi:"timeCreated"`
	// The time the the DataAsset was updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringOutput `pulumi:"timeUpdated"`
}

// NewDataAsset registers a new resource with the given unique name, arguments, and options.
func NewDataAsset(ctx *pulumi.Context,
	name string, args *DataAssetArgs, opts ...pulumi.ResourceOption) (*DataAsset, error) {
	if args == nil {
		return nil, errors.New("missing one or more required arguments")
	}

	if args.CompartmentId == nil {
		return nil, errors.New("invalid value for required argument 'CompartmentId'")
	}
	if args.DataSourceDetails == nil {
		return nil, errors.New("invalid value for required argument 'DataSourceDetails'")
	}
	if args.ProjectId == nil {
		return nil, errors.New("invalid value for required argument 'ProjectId'")
	}
	opts = internal.PkgResourceDefaultOpts(opts)
	var resource DataAsset
	err := ctx.RegisterResource("oci:AiAnomalyDetection/dataAsset:DataAsset", name, args, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// GetDataAsset gets an existing DataAsset resource's state with the given name, ID, and optional
// state properties that are used to uniquely qualify the lookup (nil if not required).
func GetDataAsset(ctx *pulumi.Context,
	name string, id pulumi.IDInput, state *DataAssetState, opts ...pulumi.ResourceOption) (*DataAsset, error) {
	var resource DataAsset
	err := ctx.ReadResource("oci:AiAnomalyDetection/dataAsset:DataAsset", name, id, state, &resource, opts...)
	if err != nil {
		return nil, err
	}
	return &resource, nil
}

// Input properties used for looking up and filtering DataAsset resources.
type dataAssetState struct {
	// (Updatable) The OCID for the data asset's compartment.
	CompartmentId *string `pulumi:"compartmentId"`
	// Possible data sources
	DataSourceDetails *DataAssetDataSourceDetails `pulumi:"dataSourceDetails"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A short description of the Ai data asset
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// OCID of Private Endpoint.
	PrivateEndpointId *string `pulumi:"privateEndpointId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the data asset.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId *string `pulumi:"projectId"`
	// The lifecycle state of the Data Asset.
	State *string `pulumi:"state"`
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags map[string]string `pulumi:"systemTags"`
	// The time the the DataAsset was created. An RFC3339 formatted datetime string
	TimeCreated *string `pulumi:"timeCreated"`
	// The time the the DataAsset was updated. An RFC3339 formatted datetime string
	TimeUpdated *string `pulumi:"timeUpdated"`
}

type DataAssetState struct {
	// (Updatable) The OCID for the data asset's compartment.
	CompartmentId pulumi.StringPtrInput
	// Possible data sources
	DataSourceDetails DataAssetDataSourceDetailsPtrInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A short description of the Ai data asset
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// OCID of Private Endpoint.
	PrivateEndpointId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the data asset.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId pulumi.StringPtrInput
	// The lifecycle state of the Data Asset.
	State pulumi.StringPtrInput
	// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
	SystemTags pulumi.StringMapInput
	// The time the the DataAsset was created. An RFC3339 formatted datetime string
	TimeCreated pulumi.StringPtrInput
	// The time the the DataAsset was updated. An RFC3339 formatted datetime string
	TimeUpdated pulumi.StringPtrInput
}

func (DataAssetState) ElementType() reflect.Type {
	return reflect.TypeOf((*dataAssetState)(nil)).Elem()
}

type dataAssetArgs struct {
	// (Updatable) The OCID for the data asset's compartment.
	CompartmentId string `pulumi:"compartmentId"`
	// Possible data sources
	DataSourceDetails DataAssetDataSourceDetails `pulumi:"dataSourceDetails"`
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags map[string]string `pulumi:"definedTags"`
	// (Updatable) A short description of the Ai data asset
	Description *string `pulumi:"description"`
	// (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
	DisplayName *string `pulumi:"displayName"`
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags map[string]string `pulumi:"freeformTags"`
	// OCID of Private Endpoint.
	PrivateEndpointId *string `pulumi:"privateEndpointId"`
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the data asset.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId string `pulumi:"projectId"`
}

// The set of arguments for constructing a DataAsset resource.
type DataAssetArgs struct {
	// (Updatable) The OCID for the data asset's compartment.
	CompartmentId pulumi.StringInput
	// Possible data sources
	DataSourceDetails DataAssetDataSourceDetailsInput
	// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
	DefinedTags pulumi.StringMapInput
	// (Updatable) A short description of the Ai data asset
	Description pulumi.StringPtrInput
	// (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
	DisplayName pulumi.StringPtrInput
	// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
	FreeformTags pulumi.StringMapInput
	// OCID of Private Endpoint.
	PrivateEndpointId pulumi.StringPtrInput
	// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the data asset.
	//
	// ** IMPORTANT **
	// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
	ProjectId pulumi.StringInput
}

func (DataAssetArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*dataAssetArgs)(nil)).Elem()
}

type DataAssetInput interface {
	pulumi.Input

	ToDataAssetOutput() DataAssetOutput
	ToDataAssetOutputWithContext(ctx context.Context) DataAssetOutput
}

func (*DataAsset) ElementType() reflect.Type {
	return reflect.TypeOf((**DataAsset)(nil)).Elem()
}

func (i *DataAsset) ToDataAssetOutput() DataAssetOutput {
	return i.ToDataAssetOutputWithContext(context.Background())
}

func (i *DataAsset) ToDataAssetOutputWithContext(ctx context.Context) DataAssetOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataAssetOutput)
}

// DataAssetArrayInput is an input type that accepts DataAssetArray and DataAssetArrayOutput values.
// You can construct a concrete instance of `DataAssetArrayInput` via:
//
//	DataAssetArray{ DataAssetArgs{...} }
type DataAssetArrayInput interface {
	pulumi.Input

	ToDataAssetArrayOutput() DataAssetArrayOutput
	ToDataAssetArrayOutputWithContext(context.Context) DataAssetArrayOutput
}

type DataAssetArray []DataAssetInput

func (DataAssetArray) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DataAsset)(nil)).Elem()
}

func (i DataAssetArray) ToDataAssetArrayOutput() DataAssetArrayOutput {
	return i.ToDataAssetArrayOutputWithContext(context.Background())
}

func (i DataAssetArray) ToDataAssetArrayOutputWithContext(ctx context.Context) DataAssetArrayOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataAssetArrayOutput)
}

// DataAssetMapInput is an input type that accepts DataAssetMap and DataAssetMapOutput values.
// You can construct a concrete instance of `DataAssetMapInput` via:
//
//	DataAssetMap{ "key": DataAssetArgs{...} }
type DataAssetMapInput interface {
	pulumi.Input

	ToDataAssetMapOutput() DataAssetMapOutput
	ToDataAssetMapOutputWithContext(context.Context) DataAssetMapOutput
}

type DataAssetMap map[string]DataAssetInput

func (DataAssetMap) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DataAsset)(nil)).Elem()
}

func (i DataAssetMap) ToDataAssetMapOutput() DataAssetMapOutput {
	return i.ToDataAssetMapOutputWithContext(context.Background())
}

func (i DataAssetMap) ToDataAssetMapOutputWithContext(ctx context.Context) DataAssetMapOutput {
	return pulumi.ToOutputWithContext(ctx, i).(DataAssetMapOutput)
}

type DataAssetOutput struct{ *pulumi.OutputState }

func (DataAssetOutput) ElementType() reflect.Type {
	return reflect.TypeOf((**DataAsset)(nil)).Elem()
}

func (o DataAssetOutput) ToDataAssetOutput() DataAssetOutput {
	return o
}

func (o DataAssetOutput) ToDataAssetOutputWithContext(ctx context.Context) DataAssetOutput {
	return o
}

// (Updatable) The OCID for the data asset's compartment.
func (o DataAssetOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.CompartmentId }).(pulumi.StringOutput)
}

// Possible data sources
func (o DataAssetOutput) DataSourceDetails() DataAssetDataSourceDetailsOutput {
	return o.ApplyT(func(v *DataAsset) DataAssetDataSourceDetailsOutput { return v.DataSourceDetails }).(DataAssetDataSourceDetailsOutput)
}

// (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{"foo-namespace.bar-key": "value"}`
func (o DataAssetOutput) DefinedTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringMapOutput { return v.DefinedTags }).(pulumi.StringMapOutput)
}

// (Updatable) A short description of the Ai data asset
func (o DataAssetOutput) Description() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.Description }).(pulumi.StringOutput)
}

// (Updatable) A user-friendly display name for the resource. It does not have to be unique and can be modified. Avoid entering confidential information.
func (o DataAssetOutput) DisplayName() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.DisplayName }).(pulumi.StringOutput)
}

// (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{"bar-key": "value"}`
func (o DataAssetOutput) FreeformTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringMapOutput { return v.FreeformTags }).(pulumi.StringMapOutput)
}

// OCID of Private Endpoint.
func (o DataAssetOutput) PrivateEndpointId() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.PrivateEndpointId }).(pulumi.StringOutput)
}

// The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the project to associate with the data asset.
//
// ** IMPORTANT **
// Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
func (o DataAssetOutput) ProjectId() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.ProjectId }).(pulumi.StringOutput)
}

// The lifecycle state of the Data Asset.
func (o DataAssetOutput) State() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.State }).(pulumi.StringOutput)
}

// Usage of system tag keys. These predefined keys are scoped to namespaces. Example: `{"orcl-cloud.free-tier-retained": "true"}`
func (o DataAssetOutput) SystemTags() pulumi.StringMapOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringMapOutput { return v.SystemTags }).(pulumi.StringMapOutput)
}

// The time the the DataAsset was created. An RFC3339 formatted datetime string
func (o DataAssetOutput) TimeCreated() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.TimeCreated }).(pulumi.StringOutput)
}

// The time the the DataAsset was updated. An RFC3339 formatted datetime string
func (o DataAssetOutput) TimeUpdated() pulumi.StringOutput {
	return o.ApplyT(func(v *DataAsset) pulumi.StringOutput { return v.TimeUpdated }).(pulumi.StringOutput)
}

type DataAssetArrayOutput struct{ *pulumi.OutputState }

func (DataAssetArrayOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*[]*DataAsset)(nil)).Elem()
}

func (o DataAssetArrayOutput) ToDataAssetArrayOutput() DataAssetArrayOutput {
	return o
}

func (o DataAssetArrayOutput) ToDataAssetArrayOutputWithContext(ctx context.Context) DataAssetArrayOutput {
	return o
}

func (o DataAssetArrayOutput) Index(i pulumi.IntInput) DataAssetOutput {
	return pulumi.All(o, i).ApplyT(func(vs []interface{}) *DataAsset {
		return vs[0].([]*DataAsset)[vs[1].(int)]
	}).(DataAssetOutput)
}

type DataAssetMapOutput struct{ *pulumi.OutputState }

func (DataAssetMapOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*map[string]*DataAsset)(nil)).Elem()
}

func (o DataAssetMapOutput) ToDataAssetMapOutput() DataAssetMapOutput {
	return o
}

func (o DataAssetMapOutput) ToDataAssetMapOutputWithContext(ctx context.Context) DataAssetMapOutput {
	return o
}

func (o DataAssetMapOutput) MapIndex(k pulumi.StringInput) DataAssetOutput {
	return pulumi.All(o, k).ApplyT(func(vs []interface{}) *DataAsset {
		return vs[0].(map[string]*DataAsset)[vs[1].(string)]
	}).(DataAssetOutput)
}

func init() {
	pulumi.RegisterInputType(reflect.TypeOf((*DataAssetInput)(nil)).Elem(), &DataAsset{})
	pulumi.RegisterInputType(reflect.TypeOf((*DataAssetArrayInput)(nil)).Elem(), DataAssetArray{})
	pulumi.RegisterInputType(reflect.TypeOf((*DataAssetMapInput)(nil)).Elem(), DataAssetMap{})
	pulumi.RegisterOutputType(DataAssetOutput{})
	pulumi.RegisterOutputType(DataAssetArrayOutput{})
	pulumi.RegisterOutputType(DataAssetMapOutput{})
}
