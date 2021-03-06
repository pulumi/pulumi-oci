// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Identity;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Identity.DomainArgs;
import com.pulumi.oci.Identity.inputs.DomainState;
import com.pulumi.oci.Identity.outputs.DomainReplicaRegion;
import com.pulumi.oci.Utilities;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.List;
import java.util.Map;
import javax.annotation.Nullable;

/**
 * This resource provides the Domain resource in Oracle Cloud Infrastructure Identity service.
 * 
 * Creates a new domain in the tenancy with domain home in {@code homeRegion}. This is an asynchronous call - where, at start,
 * {@code lifecycleState} of this domain is set to CREATING and {@code lifecycleDetails} to UPDATING. On domain creation completion
 * this Domain&#39;s {@code lifecycleState} will be set to ACTIVE and {@code lifecycleDetails} to null.
 * 
 * To track progress, HTTP GET on /iamWorkRequests/{iamWorkRequestsId} endpoint will provide
 * the async operation&#39;s status.
 * 
 * After creating a `Domain`, make sure its `lifecycleState` changes from CREATING to ACTIVE
 * before using it.
 * If the domain&#39;s {@code displayName} already exists, returns 400 BAD REQUEST.
 * If any one of admin related fields are provided and one of the following 3 fields
 * - {@code adminEmail}, {@code adminLastName} and {@code adminUserName} - is not provided,
 *   returns 400 BAD REQUEST.
 * - If {@code isNotificationBypassed} is NOT provided when admin information is provided,
 *   returns 400 BAD REQUEST.
 * - If any internal error occurs, return 500 INTERNAL SERVER ERROR.
 * 
 * ## Example Usage
 * 
 * ## Import
 * 
 * Domains can be imported using the `id`, e.g.
 * 
 * ```sh
 *  $ pulumi import oci:Identity/domain:Domain test_domain &#34;id&#34;
 * ```
 * 
 */
@ResourceType(type="oci:Identity/domain:Domain")
public class Domain extends com.pulumi.resources.CustomResource {
    /**
     * The admin email address
     * 
     */
    @Export(name="adminEmail", type=String.class, parameters={})
    private Output<String> adminEmail;

    /**
     * @return The admin email address
     * 
     */
    public Output<String> adminEmail() {
        return this.adminEmail;
    }
    /**
     * The admin first name
     * 
     */
    @Export(name="adminFirstName", type=String.class, parameters={})
    private Output<String> adminFirstName;

    /**
     * @return The admin first name
     * 
     */
    public Output<String> adminFirstName() {
        return this.adminFirstName;
    }
    /**
     * The admin last name
     * 
     */
    @Export(name="adminLastName", type=String.class, parameters={})
    private Output<String> adminLastName;

    /**
     * @return The admin last name
     * 
     */
    public Output<String> adminLastName() {
        return this.adminLastName;
    }
    /**
     * The admin user name
     * 
     */
    @Export(name="adminUserName", type=String.class, parameters={})
    private Output<String> adminUserName;

    /**
     * @return The admin user name
     * 
     */
    public Output<String> adminUserName() {
        return this.adminUserName;
    }
    /**
     * (Updatable) The OCID of the Compartment where domain is created
     * 
     */
    @Export(name="compartmentId", type=String.class, parameters={})
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The OCID of the Compartment where domain is created
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }
    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Export(name="definedTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Output<Map<String,Object>> definedTags() {
        return this.definedTags;
    }
    /**
     * (Updatable) Domain entity description
     * 
     */
    @Export(name="description", type=String.class, parameters={})
    private Output<String> description;

    /**
     * @return (Updatable) Domain entity description
     * 
     */
    public Output<String> description() {
        return this.description;
    }
    /**
     * (Updatable) The mutable display name of the domain.
     * 
     */
    @Export(name="displayName", type=String.class, parameters={})
    private Output<String> displayName;

    /**
     * @return (Updatable) The mutable display name of the domain.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }
    /**
     * (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Export(name="freeformTags", type=Map.class, parameters={String.class, Object.class})
    private Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Free-form tags for this resource. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Output<Map<String,Object>> freeformTags() {
        return this.freeformTags;
    }
    /**
     * The region&#39;s name. See [Regions and Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm) for the full list of supported region names.  Example: `us-phoenix-1`
     * 
     */
    @Export(name="homeRegion", type=String.class, parameters={})
    private Output<String> homeRegion;

    /**
     * @return The region&#39;s name. See [Regions and Availability Domains](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/regions.htm) for the full list of supported region names.  Example: `us-phoenix-1`
     * 
     */
    public Output<String> homeRegion() {
        return this.homeRegion;
    }
    /**
     * Region specific domain URL.
     * 
     */
    @Export(name="homeRegionUrl", type=String.class, parameters={})
    private Output<String> homeRegionUrl;

    /**
     * @return Region specific domain URL.
     * 
     */
    public Output<String> homeRegionUrl() {
        return this.homeRegionUrl;
    }
    /**
     * (Updatable) Indicates whether domain is hidden on login screen or not.
     * 
     */
    @Export(name="isHiddenOnLogin", type=Boolean.class, parameters={})
    private Output<Boolean> isHiddenOnLogin;

    /**
     * @return (Updatable) Indicates whether domain is hidden on login screen or not.
     * 
     */
    public Output<Boolean> isHiddenOnLogin() {
        return this.isHiddenOnLogin;
    }
    /**
     * Indicates if admin user created in IDCS stripe would like to receive notification like welcome email or not. Required field only if admin information is provided, otherwise optional.
     * 
     */
    @Export(name="isNotificationBypassed", type=Boolean.class, parameters={})
    private Output<Boolean> isNotificationBypassed;

    /**
     * @return Indicates if admin user created in IDCS stripe would like to receive notification like welcome email or not. Required field only if admin information is provided, otherwise optional.
     * 
     */
    public Output<Boolean> isNotificationBypassed() {
        return this.isNotificationBypassed;
    }
    /**
     * Optional field to indicate whether users in the domain are required to have a primary email address or not Defaults to true
     * 
     */
    @Export(name="isPrimaryEmailRequired", type=Boolean.class, parameters={})
    private Output<Boolean> isPrimaryEmailRequired;

    /**
     * @return Optional field to indicate whether users in the domain are required to have a primary email address or not Defaults to true
     * 
     */
    public Output<Boolean> isPrimaryEmailRequired() {
        return this.isPrimaryEmailRequired;
    }
    /**
     * The License type of Domain
     * 
     */
    @Export(name="licenseType", type=String.class, parameters={})
    private Output<String> licenseType;

    /**
     * @return The License type of Domain
     * 
     */
    public Output<String> licenseType() {
        return this.licenseType;
    }
    /**
     * Any additional details about the current state of the Domain.
     * 
     */
    @Export(name="lifecycleDetails", type=String.class, parameters={})
    private Output<String> lifecycleDetails;

    /**
     * @return Any additional details about the current state of the Domain.
     * 
     */
    public Output<String> lifecycleDetails() {
        return this.lifecycleDetails;
    }
    /**
     * The regions domain is replication to.
     * 
     */
    @Export(name="replicaRegions", type=List.class, parameters={DomainReplicaRegion.class})
    private Output<List<DomainReplicaRegion>> replicaRegions;

    /**
     * @return The regions domain is replication to.
     * 
     */
    public Output<List<DomainReplicaRegion>> replicaRegions() {
        return this.replicaRegions;
    }
    /**
     * The current state.
     * 
     */
    @Export(name="state", type=String.class, parameters={})
    private Output<String> state;

    /**
     * @return The current state.
     * 
     */
    public Output<String> state() {
        return this.state;
    }
    /**
     * Date and time the domain was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Export(name="timeCreated", type=String.class, parameters={})
    private Output<String> timeCreated;

    /**
     * @return Date and time the domain was created, in the format defined by RFC3339.  Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Output<String> timeCreated() {
        return this.timeCreated;
    }
    /**
     * The type of the domain.
     * 
     */
    @Export(name="type", type=String.class, parameters={})
    private Output<String> type;

    /**
     * @return The type of the domain.
     * 
     */
    public Output<String> type() {
        return this.type;
    }
    /**
     * Region agnostic domain URL.
     * 
     */
    @Export(name="url", type=String.class, parameters={})
    private Output<String> url;

    /**
     * @return Region agnostic domain URL.
     * 
     */
    public Output<String> url() {
        return this.url;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public Domain(String name) {
        this(name, DomainArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public Domain(String name, DomainArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public Domain(String name, DomainArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Identity/domain:Domain", name, args == null ? DomainArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private Domain(String name, Output<String> id, @Nullable DomainState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Identity/domain:Domain", name, state, makeResourceOptions(options, id));
    }

    private static com.pulumi.resources.CustomResourceOptions makeResourceOptions(@Nullable com.pulumi.resources.CustomResourceOptions options, @Nullable Output<String> id) {
        var defaultOptions = com.pulumi.resources.CustomResourceOptions.builder()
            .version(Utilities.getVersion())
            .build();
        return com.pulumi.resources.CustomResourceOptions.merge(defaultOptions, options, id);
    }

    /**
     * Get an existing Host resource's state with the given name, ID, and optional extra
     * properties used to qualify the lookup.
     *
     * @param name The _unique_ name of the resulting resource.
     * @param id The _unique_ provider ID of the resource to lookup.
     * @param state
     * @param options Optional settings to control the behavior of the CustomResource.
     */
    public static Domain get(String name, Output<String> id, @Nullable DomainState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new Domain(name, id, state, options);
    }
}
