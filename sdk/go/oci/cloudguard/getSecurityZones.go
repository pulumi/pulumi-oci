// Code generated by the Pulumi Terraform Bridge (tfgen) Tool DO NOT EDIT.
// *** WARNING: Do not edit by hand unless you're certain you know what you are doing! ***

package cloudguard

import (
	"context"
	"reflect"

	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

// This data source provides the list of Security Zones in Oracle Cloud Infrastructure Cloud Guard service.
//
// Gets a list of all security zones in a compartment.
//
// ## Example Usage
//
// ```go
// package main
//
// import (
//
//	"github.com/pulumi/pulumi-oci/sdk/go/oci/CloudGuard"
//	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
//
// )
//
//	func main() {
//		pulumi.Run(func(ctx *pulumi.Context) error {
//			_, err := CloudGuard.GetSecurityZones(ctx, &cloudguard.GetSecurityZonesArgs{
//				CompartmentId:                    _var.Compartment_id,
//				DisplayName:                      pulumi.StringRef(_var.Security_zone_display_name),
//				Id:                               pulumi.StringRef(_var.Security_zone_id),
//				IsRequiredSecurityZonesInSubtree: pulumi.BoolRef(_var.Security_zone_is_required_security_zones_in_subtree),
//				SecurityRecipeId:                 pulumi.StringRef(oci_cloud_guard_security_recipe.Test_security_recipe.Id),
//				State:                            pulumi.StringRef(_var.Security_zone_state),
//			}, nil)
//			if err != nil {
//				return err
//			}
//			return nil
//		})
//	}
//
// ```
func GetSecurityZones(ctx *pulumi.Context, args *GetSecurityZonesArgs, opts ...pulumi.InvokeOption) (*GetSecurityZonesResult, error) {
	var rv GetSecurityZonesResult
	err := ctx.Invoke("oci:CloudGuard/getSecurityZones:getSecurityZones", args, &rv, opts...)
	if err != nil {
		return nil, err
	}
	return &rv, nil
}

// A collection of arguments for invoking getSecurityZones.
type GetSecurityZonesArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId string `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetSecurityZonesFilter `pulumi:"filters"`
	// The unique identifier of the security zone (`SecurityZone`)
	Id *string `pulumi:"id"`
	// security zones in the subtree
	IsRequiredSecurityZonesInSubtree *bool `pulumi:"isRequiredSecurityZonesInSubtree"`
	// The unique identifier of the security zone recipe (`SecurityRecipe`)
	SecurityRecipeId *string `pulumi:"securityRecipeId"`
	// The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
	State *string `pulumi:"state"`
}

// A collection of values returned by getSecurityZones.
type GetSecurityZonesResult struct {
	// The OCID of the compartment for the security zone
	CompartmentId string `pulumi:"compartmentId"`
	// The security zone's name
	DisplayName *string                  `pulumi:"displayName"`
	Filters     []GetSecurityZonesFilter `pulumi:"filters"`
	// Unique identifier that is immutable on creation
	Id                               *string `pulumi:"id"`
	IsRequiredSecurityZonesInSubtree *bool   `pulumi:"isRequiredSecurityZonesInSubtree"`
	SecurityRecipeId                 *string `pulumi:"securityRecipeId"`
	// The list of security_zone_collection.
	SecurityZoneCollections []GetSecurityZonesSecurityZoneCollection `pulumi:"securityZoneCollections"`
	// The current state of the security zone
	State *string `pulumi:"state"`
}

func GetSecurityZonesOutput(ctx *pulumi.Context, args GetSecurityZonesOutputArgs, opts ...pulumi.InvokeOption) GetSecurityZonesResultOutput {
	return pulumi.ToOutputWithContext(context.Background(), args).
		ApplyT(func(v interface{}) (GetSecurityZonesResult, error) {
			args := v.(GetSecurityZonesArgs)
			r, err := GetSecurityZones(ctx, &args, opts...)
			var s GetSecurityZonesResult
			if r != nil {
				s = *r
			}
			return s, err
		}).(GetSecurityZonesResultOutput)
}

// A collection of arguments for invoking getSecurityZones.
type GetSecurityZonesOutputArgs struct {
	// The ID of the compartment in which to list resources.
	CompartmentId pulumi.StringInput `pulumi:"compartmentId"`
	// A filter to return only resources that match the entire display name given.
	DisplayName pulumi.StringPtrInput            `pulumi:"displayName"`
	Filters     GetSecurityZonesFilterArrayInput `pulumi:"filters"`
	// The unique identifier of the security zone (`SecurityZone`)
	Id pulumi.StringPtrInput `pulumi:"id"`
	// security zones in the subtree
	IsRequiredSecurityZonesInSubtree pulumi.BoolPtrInput `pulumi:"isRequiredSecurityZonesInSubtree"`
	// The unique identifier of the security zone recipe (`SecurityRecipe`)
	SecurityRecipeId pulumi.StringPtrInput `pulumi:"securityRecipeId"`
	// The field life cycle state. Only one state can be provided. Default value for state is active. If no value is specified state is active.
	State pulumi.StringPtrInput `pulumi:"state"`
}

func (GetSecurityZonesOutputArgs) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecurityZonesArgs)(nil)).Elem()
}

// A collection of values returned by getSecurityZones.
type GetSecurityZonesResultOutput struct{ *pulumi.OutputState }

func (GetSecurityZonesResultOutput) ElementType() reflect.Type {
	return reflect.TypeOf((*GetSecurityZonesResult)(nil)).Elem()
}

func (o GetSecurityZonesResultOutput) ToGetSecurityZonesResultOutput() GetSecurityZonesResultOutput {
	return o
}

func (o GetSecurityZonesResultOutput) ToGetSecurityZonesResultOutputWithContext(ctx context.Context) GetSecurityZonesResultOutput {
	return o
}

// The OCID of the compartment for the security zone
func (o GetSecurityZonesResultOutput) CompartmentId() pulumi.StringOutput {
	return o.ApplyT(func(v GetSecurityZonesResult) string { return v.CompartmentId }).(pulumi.StringOutput)
}

// The security zone's name
func (o GetSecurityZonesResultOutput) DisplayName() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityZonesResult) *string { return v.DisplayName }).(pulumi.StringPtrOutput)
}

func (o GetSecurityZonesResultOutput) Filters() GetSecurityZonesFilterArrayOutput {
	return o.ApplyT(func(v GetSecurityZonesResult) []GetSecurityZonesFilter { return v.Filters }).(GetSecurityZonesFilterArrayOutput)
}

// Unique identifier that is immutable on creation
func (o GetSecurityZonesResultOutput) Id() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityZonesResult) *string { return v.Id }).(pulumi.StringPtrOutput)
}

func (o GetSecurityZonesResultOutput) IsRequiredSecurityZonesInSubtree() pulumi.BoolPtrOutput {
	return o.ApplyT(func(v GetSecurityZonesResult) *bool { return v.IsRequiredSecurityZonesInSubtree }).(pulumi.BoolPtrOutput)
}

func (o GetSecurityZonesResultOutput) SecurityRecipeId() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityZonesResult) *string { return v.SecurityRecipeId }).(pulumi.StringPtrOutput)
}

// The list of security_zone_collection.
func (o GetSecurityZonesResultOutput) SecurityZoneCollections() GetSecurityZonesSecurityZoneCollectionArrayOutput {
	return o.ApplyT(func(v GetSecurityZonesResult) []GetSecurityZonesSecurityZoneCollection {
		return v.SecurityZoneCollections
	}).(GetSecurityZonesSecurityZoneCollectionArrayOutput)
}

// The current state of the security zone
func (o GetSecurityZonesResultOutput) State() pulumi.StringPtrOutput {
	return o.ApplyT(func(v GetSecurityZonesResult) *string { return v.State }).(pulumi.StringPtrOutput)
}

func init() {
	pulumi.RegisterOutputType(GetSecurityZonesResultOutput{})
}