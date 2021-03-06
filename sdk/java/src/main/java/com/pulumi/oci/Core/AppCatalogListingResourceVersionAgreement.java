// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Core;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Export;
import com.pulumi.core.annotations.ResourceType;
import com.pulumi.core.internal.Codegen;
import com.pulumi.oci.Core.AppCatalogListingResourceVersionAgreementArgs;
import com.pulumi.oci.Core.inputs.AppCatalogListingResourceVersionAgreementState;
import com.pulumi.oci.Utilities;
import java.lang.String;
import javax.annotation.Nullable;

/**
 * The `oci.Core.AppCatalogListingResourceVersionAgreement` resource creates AppCatalogListingResourceVersionAgreement for a particular resource version of a listing.
 * 
 * ## Example Usage
 * 
 */
@ResourceType(type="oci:Core/appCatalogListingResourceVersionAgreement:AppCatalogListingResourceVersionAgreement")
public class AppCatalogListingResourceVersionAgreement extends com.pulumi.resources.CustomResource {
    /**
     * EULA link
     * 
     */
    @Export(name="eulaLink", type=String.class, parameters={})
    private Output<String> eulaLink;

    /**
     * @return EULA link
     * 
     */
    public Output<String> eulaLink() {
        return this.eulaLink;
    }
    /**
     * The OCID of the listing.
     * 
     */
    @Export(name="listingId", type=String.class, parameters={})
    private Output<String> listingId;

    /**
     * @return The OCID of the listing.
     * 
     */
    public Output<String> listingId() {
        return this.listingId;
    }
    /**
     * Listing Resource Version.
     * 
     */
    @Export(name="listingResourceVersion", type=String.class, parameters={})
    private Output<String> listingResourceVersion;

    /**
     * @return Listing Resource Version.
     * 
     */
    public Output<String> listingResourceVersion() {
        return this.listingResourceVersion;
    }
    /**
     * Oracle TOU link
     * 
     */
    @Export(name="oracleTermsOfUseLink", type=String.class, parameters={})
    private Output<String> oracleTermsOfUseLink;

    /**
     * @return Oracle TOU link
     * 
     */
    public Output<String> oracleTermsOfUseLink() {
        return this.oracleTermsOfUseLink;
    }
    /**
     * A generated signature for this agreement retrieval operation which should be used in the create subscription call.
     * 
     */
    @Export(name="signature", type=String.class, parameters={})
    private Output<String> signature;

    /**
     * @return A generated signature for this agreement retrieval operation which should be used in the create subscription call.
     * 
     */
    public Output<String> signature() {
        return this.signature;
    }
    /**
     * Date and time the agreements were retrieved, in RFC3339 format. Example: `2018-03-20T12:32:53.532Z`
     * 
     */
    @Export(name="timeRetrieved", type=String.class, parameters={})
    private Output<String> timeRetrieved;

    /**
     * @return Date and time the agreements were retrieved, in RFC3339 format. Example: `2018-03-20T12:32:53.532Z`
     * 
     */
    public Output<String> timeRetrieved() {
        return this.timeRetrieved;
    }

    /**
     *
     * @param name The _unique_ name of the resulting resource.
     */
    public AppCatalogListingResourceVersionAgreement(String name) {
        this(name, AppCatalogListingResourceVersionAgreementArgs.Empty);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     */
    public AppCatalogListingResourceVersionAgreement(String name, AppCatalogListingResourceVersionAgreementArgs args) {
        this(name, args, null);
    }
    /**
     *
     * @param name The _unique_ name of the resulting resource.
     * @param args The arguments to use to populate this resource's properties.
     * @param options A bag of options that control this resource's behavior.
     */
    public AppCatalogListingResourceVersionAgreement(String name, AppCatalogListingResourceVersionAgreementArgs args, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/appCatalogListingResourceVersionAgreement:AppCatalogListingResourceVersionAgreement", name, args == null ? AppCatalogListingResourceVersionAgreementArgs.Empty : args, makeResourceOptions(options, Codegen.empty()));
    }

    private AppCatalogListingResourceVersionAgreement(String name, Output<String> id, @Nullable AppCatalogListingResourceVersionAgreementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        super("oci:Core/appCatalogListingResourceVersionAgreement:AppCatalogListingResourceVersionAgreement", name, state, makeResourceOptions(options, id));
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
    public static AppCatalogListingResourceVersionAgreement get(String name, Output<String> id, @Nullable AppCatalogListingResourceVersionAgreementState state, @Nullable com.pulumi.resources.CustomResourceOptions options) {
        return new AppCatalogListingResourceVersionAgreement(name, id, state, options);
    }
}
