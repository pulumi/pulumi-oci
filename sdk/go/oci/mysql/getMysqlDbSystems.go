// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package mysql

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Mysql Db Systems in Oracle Cloud Infrastructure MySQL Database service.
//
// Get a list of DB Systems in the specified compartment.
// The default sort order is by timeUpdated, descending.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/Mysql"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := Mysql.GetMysqlDbSystems(ctx, &mysql.GetMysqlDbSystemsArgs{
//				CompartmentId:              _var.Compartment_id,
//				ConfigurationId:            pulumi.StringRef(_var.Mysql_configuration_id),
//				DbSystemId:                 pulumi.StringRef(oci_mysql_mysql_db_system.Test_db_system.Id),
//				DisplayName:                pulumi.StringRef(_var.Mysql_db_system_display_name),
//				IsAnalyticsClusterAttached: pulumi.BoolRef(_var.Mysql_db_system_is_analytics_cluster_attached),
//				IsHeatWaveClusterAttached:  pulumi.BoolRef(_var.Mysql_db_system_is_heat_wave_cluster_attached),
//				IsUpToDate:                 pulumi.BoolRef(_var.Mysql_db_system_is_up_to_date),
//				State:                      pulumi.StringRef(_var.Mysql_db_system_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetMysqlDbSystems(ctx *pulumi.Context, args *GetMysqlDbSystemsArgs, opts ...pulumi.InvokeOption) (*GetMysqlDbSystemsResult, error) {
	var rv GetMysqlDbSystemsResult
	err := ctx.Invoke("oci:Mysql/getMysqlDbSystems:getMysqlDbSystems", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getMysqlDbSystems.
type GetMysqlDbSystemsArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId string `pulumi:"compartmentId"`
	// The requested Configuration instance.
	ConfigurationId *string `pulumi:"configurationId"`
	// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId *string `pulumi:"dbSystemId"`
	// A filter to return only the resource matching the given display name exactly.
	DisplayName *string                   `pulumi:"displayName"`
	Filters     []GetMysqlDbSystemsFilter `pulumi:"filters"`
	// DEPRECATED -- please use HeatWave API instead. If true, return only DB Systems with an Analytics Cluster attached, if false return only DB Systems with no Analytics Cluster attached. If not present, return all DB Systems.
	IsAnalyticsClusterAttached *bool `pulumi:"isAnalyticsClusterAttached"`
	// If true, return only DB Systems with a HeatWave cluster attached, if false return only DB Systems with no HeatWave cluster attached. If not present, return all DB Systems.
	IsHeatWaveClusterAttached *bool `pulumi:"isHeatWaveClusterAttached"`
	// Filter instances if they are using the latest revision of the Configuration they are associated with.
	IsUpToDate *bool `pulumi:"isUpToDate"`
	// DbSystem Lifecycle State
	State *string `pulumi:"state"`
}

// A collection of values returned by getMysqlDbSystems.
type GetMysqlDbSystemsResult struct {
	// The OCID of the compartment the DB System belongs in.
	CompartmentId string `pulumi:"compartmentId"`
	// The OCID of the Configuration to be used for Instances in this DB System.
	ConfigurationId *string `pulumi:"configurationId"`
	// The OCID of the DB System from which a backup shall be selected to be restored when creating the new DB System. Use this together with recovery point to perform a point in time recovery operation.
	DbSystemId *string `pulumi:"dbSystemId"`
	// The list of db_systems.
	DbSystems []GetMysqlDbSystemsDbSystem `pulumi:"dbSystems"`
	// The user-friendly name for the DB System. It does not have to be unique.
	DisplayName *string                   `pulumi:"displayName"`
	Filters     []GetMysqlDbSystemsFilter `pulumi:"filters"`
	// The provider-assigned unique ID for this managed resource.
	Id string `pulumi:"id"`
	// DEPRECATED -- please use `isHeatWaveClusterAttached` instead. If the DB System has an Analytics Cluster attached.
	IsAnalyticsClusterAttached *bool `pulumi:"isAnalyticsClusterAttached"`
	// If the DB System has a HeatWave Cluster attached.
	IsHeatWaveClusterAttached *bool `pulumi:"isHeatWaveClusterAttached"`
	IsUpToDate                *bool `pulumi:"isUpToDate"`
	// The current state of the DB System.
	State *string `pulumi:"state"`
}

func GetMysqlDbSystemsOutput(ctx *pulumi.Context, args GetMysqlDbSystemsOutputArgs, opts ...pulumi.InvokeOption) GetMysqlDbSystemsResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetMysqlDbSystemsResult, error) {
			args := v.(GetMysqlDbSystemsArgs)
			r, err := GetMysqlDbSystems(ctx, &args, opts...)
			var s GetMysqlDbSystemsResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetMysqlDbSystemsResultOutput)
}

// A collection of arguments for invoking getMysqlDbSystems.
type GetMysqlDbSystemsOutputArgs struct {
	// The compartment [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// The requested Configuration instance.
	ConfigurationId pulumi.StringPtrInput `pulumi:"configurationId"`
	// The DB System [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm).
	DbSystemId pulumi.StringPtrInput `pulumi:"dbSystemId"`
	// A filter to return only the resource matching the given display name exactly.
	DisplayName pulumi.StringPtrInput             `pulumi:"displayName"`
	Filters     GetMysqlDbSystemsFilterArrayInput `pulumi:"filters"`
	// DEPRECATED -- please use HeatWave API instead. If true, return only DB Systems with an Analytics Cluster attached, if false return only DB Systems with no Analytics Cluster attached. If not present, return all DB Systems.
	IsAnalyticsClusterAttached pulumi.BoolPtrInput `pulumi:"isAnalyticsClusterAttached"`
	// If true, return only DB Systems with a HeatWave cluster attached, if false return only DB Systems with no HeatWave cluster attached. If not present, return all DB Systems.
	IsHeatWaveClusterAttached pulumi.BoolPtrInput `pulumi:"isHeatWaveClusterAttached"`
	// Filter instances if they are using the latest revision of the Configuration they are associated with.
	IsUpToDate pulumi.BoolPtrInput `pulumi:"isUpToDate"`
	// DbSystem Lifecycle State
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetMysqlDbSystemsOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMysqlDbSystemsArgs)(nil)).Elem()
}

// A collection of values returned by getMysqlDbSystems.
type GetMysqlDbSystemsResultOutput struct{ *pulumi.OutputState }

func (GetMysqlDbSystemsResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetMysqlDbSystemsResult)(nil)).Elem()
}

func (o GetMysqlDbSystemsResultOutput) ToGetMysqlDbSystemsResultOutput() GetMysqlDbSystemsResultOutput {
	return o
}

func (o GetMysqlDbSystemsResultOutput) ToGetMysqlDbSystemsResultOutputWithContext(ctx context.Context) GetMysqlDbSystemsResultOutput {
	return o
}

// The OCID of the compartment the DB System belongs in.
func (o GetMysqlDbSystemsResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetMysqlDbSystemsResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The OCID of the Configuration to be used for Instances in this DB System.
func (o GetMysqlDbSystemsResultOutput) ConfigurationId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMysqlDbSystemsResult) *string { return v.ConfigurationId }).(pulumi.StringPtrOutput)
}

// The OCID of the DB System from which a backup shall be selected to be restored when creating the new DB System. Use this together with recovery point to perform a point in time recovery operation.
func (o GetMysqlDbSystemsResultOutput) DbSystemId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMysqlDbSystemsResult) *string { return v.DbSystemId }).(pulumi.StringPtrOutput)
}

// The list of db_systems.
func (o GetMysqlDbSystemsResultOutput) DbSystems() GetMysqlDbSystemsDbSystemArrayOutput {
	return o.ApplyT(func(v GetMysqlDbSystemsResult) []GetMysqlDbSystemsDbSystem { return v.DbSystems }).(GetMysqlDbSystemsDbSystemArrayOutput)
}

// The user-friendly name for the DB System. It does not have to be unique.
func (o GetMysqlDbSystemsResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMysqlDbSystemsResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetMysqlDbSystemsResultOutput) Filters() GetMysqlDbSystemsFilterArrayOutput {
	return o.ApplyT(func(v GetMysqlDbSystemsResult) []GetMysqlDbSystemsFilter { return v.Filters }).(GetMysqlDbSystemsFilterArrayOutput)
}

// The provider-assigned unique ID for this managed resource.
func (o GetMysqlDbSystemsResultOutput) Id() pulumi.StringOutput {
	return o.ApplyT(func(v GetMysqlDbSystemsResult) string { return v.Id }).(pulumi.StringOutput)
}

// DEPRECATED -- please use `isHeatWaveClusterAttached` instead. If the DB System has an Analytics Cluster attached.
func (o GetMysqlDbSystemsResultOutput) IsAnalyticsClusterAttached() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetMysqlDbSystemsResult) *bool { return v.IsAnalyticsClusterAttached }).(pulumi.BoolPtrOutput)
}

// If the DB System has a HeatWave Cluster attached.
func (o GetMysqlDbSystemsResultOutput) IsHeatWaveClusterAttached() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetMysqlDbSystemsResult) *bool { return v.IsHeatWaveClusterAttached }).(pulumi.BoolPtrOutput)
}

func (o GetMysqlDbSystemsResultOutput) IsUpToDate() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetMysqlDbSystemsResult) *bool { return v.IsUpToDate }).(pulumi.BoolPtrOutput)
}

// The current state of the DB System.
func (o GetMysqlDbSystemsResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetMysqlDbSystemsResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetMysqlDbSystemsResultOutput{})
}