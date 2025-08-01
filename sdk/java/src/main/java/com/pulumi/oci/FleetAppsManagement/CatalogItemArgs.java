// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.FleetAppsManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.FleetAppsManagement.inputs.CatalogItemCatalogSourcePayloadArgs;
import java.lang.Integer;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class CatalogItemArgs extends com.pulumi.resources.ResourceArgs {

    public static final CatalogItemArgs Empty = new CatalogItemArgs();

    /**
     * Catalog source payload.
     * 
     */
    @Import(name="catalogSourcePayload")
    private @Nullable Output<CatalogItemCatalogSourcePayloadArgs> catalogSourcePayload;

    /**
     * @return Catalog source payload.
     * 
     */
    public Optional<Output<CatalogItemCatalogSourcePayloadArgs>> catalogSourcePayload() {
        return Optional.ofNullable(this.catalogSourcePayload);
    }

    /**
     * (Updatable) An optional property when incremented triggers Clone Catalog Item. Could be set to any integer value.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="cloneCatalogItemTrigger")
    private @Nullable Output<Integer> cloneCatalogItemTrigger;

    /**
     * @return (Updatable) An optional property when incremented triggers Clone Catalog Item. Could be set to any integer value.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Optional<Output<Integer>> cloneCatalogItemTrigger() {
        return Optional.ofNullable(this.cloneCatalogItemTrigger);
    }

    /**
     * (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
    }

    /**
     * Config source type Eg: STACK_TEMPLATE_CATALOG_SOURCE, PAR_CATALOG_SOURCE, GIT_CATALOG_SOURCE, MARKETPLACE_CATALOG_SOURCE.
     * 
     */
    @Import(name="configSourceType", required=true)
    private Output<String> configSourceType;

    /**
     * @return Config source type Eg: STACK_TEMPLATE_CATALOG_SOURCE, PAR_CATALOG_SOURCE, GIT_CATALOG_SOURCE, MARKETPLACE_CATALOG_SOURCE.
     * 
     */
    public Output<String> configSourceType() {
        return this.configSourceType;
    }

    /**
     * (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,String>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) The description of the CatalogItem.
     * 
     */
    @Import(name="description", required=true)
    private Output<String> description;

    /**
     * @return (Updatable) The description of the CatalogItem.
     * 
     */
    public Output<String> description() {
        return this.description;
    }

    /**
     * (Updatable) The CatalogItem name.
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) The CatalogItem name.
     * 
     */
    public Output<String> displayName() {
        return this.displayName;
    }

    /**
     * (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,String>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,String>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The catalog listing Id.
     * 
     */
    @Import(name="listingId")
    private @Nullable Output<String> listingId;

    /**
     * @return The catalog listing Id.
     * 
     */
    public Optional<Output<String>> listingId() {
        return Optional.ofNullable(this.listingId);
    }

    /**
     * The catalog package version.
     * 
     */
    @Import(name="listingVersion")
    private @Nullable Output<String> listingVersion;

    /**
     * @return The catalog package version.
     * 
     */
    public Optional<Output<String>> listingVersion() {
        return Optional.ofNullable(this.listingVersion);
    }

    /**
     * Config package type Eg: TF_PACKAGE, NON_TF_PACKAGE, CONFIG_FILE.
     * 
     */
    @Import(name="packageType", required=true)
    private Output<String> packageType;

    /**
     * @return Config package type Eg: TF_PACKAGE, NON_TF_PACKAGE, CONFIG_FILE.
     * 
     */
    public Output<String> packageType() {
        return this.packageType;
    }

    /**
     * (Updatable) Short description about the catalog item.
     * 
     */
    @Import(name="shortDescription")
    private @Nullable Output<String> shortDescription;

    /**
     * @return (Updatable) Short description about the catalog item.
     * 
     */
    public Optional<Output<String>> shortDescription() {
        return Optional.ofNullable(this.shortDescription);
    }

    /**
     * The date and time the CatalogItem was released, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    @Import(name="timeReleased")
    private @Nullable Output<String> timeReleased;

    /**
     * @return The date and time the CatalogItem was released, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
     * 
     */
    public Optional<Output<String>> timeReleased() {
        return Optional.ofNullable(this.timeReleased);
    }

    /**
     * (Updatable) Version description about the catalog item.
     * 
     */
    @Import(name="versionDescription")
    private @Nullable Output<String> versionDescription;

    /**
     * @return (Updatable) Version description about the catalog item.
     * 
     */
    public Optional<Output<String>> versionDescription() {
        return Optional.ofNullable(this.versionDescription);
    }

    private CatalogItemArgs() {}

    private CatalogItemArgs(CatalogItemArgs $) {
        this.catalogSourcePayload = $.catalogSourcePayload;
        this.cloneCatalogItemTrigger = $.cloneCatalogItemTrigger;
        this.compartmentId = $.compartmentId;
        this.configSourceType = $.configSourceType;
        this.definedTags = $.definedTags;
        this.description = $.description;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.listingId = $.listingId;
        this.listingVersion = $.listingVersion;
        this.packageType = $.packageType;
        this.shortDescription = $.shortDescription;
        this.timeReleased = $.timeReleased;
        this.versionDescription = $.versionDescription;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(CatalogItemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private CatalogItemArgs $;

        public Builder() {
            $ = new CatalogItemArgs();
        }

        public Builder(CatalogItemArgs defaults) {
            $ = new CatalogItemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param catalogSourcePayload Catalog source payload.
         * 
         * @return builder
         * 
         */
        public Builder catalogSourcePayload(@Nullable Output<CatalogItemCatalogSourcePayloadArgs> catalogSourcePayload) {
            $.catalogSourcePayload = catalogSourcePayload;
            return this;
        }

        /**
         * @param catalogSourcePayload Catalog source payload.
         * 
         * @return builder
         * 
         */
        public Builder catalogSourcePayload(CatalogItemCatalogSourcePayloadArgs catalogSourcePayload) {
            return catalogSourcePayload(Output.of(catalogSourcePayload));
        }

        /**
         * @param cloneCatalogItemTrigger (Updatable) An optional property when incremented triggers Clone Catalog Item. Could be set to any integer value.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder cloneCatalogItemTrigger(@Nullable Output<Integer> cloneCatalogItemTrigger) {
            $.cloneCatalogItemTrigger = cloneCatalogItemTrigger;
            return this;
        }

        /**
         * @param cloneCatalogItemTrigger (Updatable) An optional property when incremented triggers Clone Catalog Item. Could be set to any integer value.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder cloneCatalogItemTrigger(Integer cloneCatalogItemTrigger) {
            return cloneCatalogItemTrigger(Output.of(cloneCatalogItemTrigger));
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the compartment.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param configSourceType Config source type Eg: STACK_TEMPLATE_CATALOG_SOURCE, PAR_CATALOG_SOURCE, GIT_CATALOG_SOURCE, MARKETPLACE_CATALOG_SOURCE.
         * 
         * @return builder
         * 
         */
        public Builder configSourceType(Output<String> configSourceType) {
            $.configSourceType = configSourceType;
            return this;
        }

        /**
         * @param configSourceType Config source type Eg: STACK_TEMPLATE_CATALOG_SOURCE, PAR_CATALOG_SOURCE, GIT_CATALOG_SOURCE, MARKETPLACE_CATALOG_SOURCE.
         * 
         * @return builder
         * 
         */
        public Builder configSourceType(String configSourceType) {
            return configSourceType(Output.of(configSourceType));
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,String>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,String> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param description (Updatable) The description of the CatalogItem.
         * 
         * @return builder
         * 
         */
        public Builder description(Output<String> description) {
            $.description = description;
            return this;
        }

        /**
         * @param description (Updatable) The description of the CatalogItem.
         * 
         * @return builder
         * 
         */
        public Builder description(String description) {
            return description(Output.of(description));
        }

        /**
         * @param displayName (Updatable) The CatalogItem name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) The CatalogItem name.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,String>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,String> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param listingId The catalog listing Id.
         * 
         * @return builder
         * 
         */
        public Builder listingId(@Nullable Output<String> listingId) {
            $.listingId = listingId;
            return this;
        }

        /**
         * @param listingId The catalog listing Id.
         * 
         * @return builder
         * 
         */
        public Builder listingId(String listingId) {
            return listingId(Output.of(listingId));
        }

        /**
         * @param listingVersion The catalog package version.
         * 
         * @return builder
         * 
         */
        public Builder listingVersion(@Nullable Output<String> listingVersion) {
            $.listingVersion = listingVersion;
            return this;
        }

        /**
         * @param listingVersion The catalog package version.
         * 
         * @return builder
         * 
         */
        public Builder listingVersion(String listingVersion) {
            return listingVersion(Output.of(listingVersion));
        }

        /**
         * @param packageType Config package type Eg: TF_PACKAGE, NON_TF_PACKAGE, CONFIG_FILE.
         * 
         * @return builder
         * 
         */
        public Builder packageType(Output<String> packageType) {
            $.packageType = packageType;
            return this;
        }

        /**
         * @param packageType Config package type Eg: TF_PACKAGE, NON_TF_PACKAGE, CONFIG_FILE.
         * 
         * @return builder
         * 
         */
        public Builder packageType(String packageType) {
            return packageType(Output.of(packageType));
        }

        /**
         * @param shortDescription (Updatable) Short description about the catalog item.
         * 
         * @return builder
         * 
         */
        public Builder shortDescription(@Nullable Output<String> shortDescription) {
            $.shortDescription = shortDescription;
            return this;
        }

        /**
         * @param shortDescription (Updatable) Short description about the catalog item.
         * 
         * @return builder
         * 
         */
        public Builder shortDescription(String shortDescription) {
            return shortDescription(Output.of(shortDescription));
        }

        /**
         * @param timeReleased The date and time the CatalogItem was released, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeReleased(@Nullable Output<String> timeReleased) {
            $.timeReleased = timeReleased;
            return this;
        }

        /**
         * @param timeReleased The date and time the CatalogItem was released, in the format defined by [RFC 3339](https://tools.ietf.org/html/rfc3339). Example: `2016-08-25T21:10:29.600Z`
         * 
         * @return builder
         * 
         */
        public Builder timeReleased(String timeReleased) {
            return timeReleased(Output.of(timeReleased));
        }

        /**
         * @param versionDescription (Updatable) Version description about the catalog item.
         * 
         * @return builder
         * 
         */
        public Builder versionDescription(@Nullable Output<String> versionDescription) {
            $.versionDescription = versionDescription;
            return this;
        }

        /**
         * @param versionDescription (Updatable) Version description about the catalog item.
         * 
         * @return builder
         * 
         */
        public Builder versionDescription(String versionDescription) {
            return versionDescription(Output.of(versionDescription));
        }

        public CatalogItemArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("CatalogItemArgs", "compartmentId");
            }
            if ($.configSourceType == null) {
                throw new MissingRequiredPropertyException("CatalogItemArgs", "configSourceType");
            }
            if ($.description == null) {
                throw new MissingRequiredPropertyException("CatalogItemArgs", "description");
            }
            if ($.displayName == null) {
                throw new MissingRequiredPropertyException("CatalogItemArgs", "displayName");
            }
            if ($.packageType == null) {
                throw new MissingRequiredPropertyException("CatalogItemArgs", "packageType");
            }
            return $;
        }
    }

}
