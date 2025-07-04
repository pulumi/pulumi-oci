// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.CapacityManagement;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class OccmDemandSignalItemArgs extends com.pulumi.resources.ResourceArgs {

    public static final OccmDemandSignalItemArgs Empty = new OccmDemandSignalItemArgs();

    /**
     * (Updatable) The name of the availability domain for which you want to request the Oracle Cloud Infrastructure resource. This is an optional parameter.
     * 
     */
    @Import(name="availabilityDomain")
    private @Nullable Output<String> availabilityDomain;

    /**
     * @return (Updatable) The name of the availability domain for which you want to request the Oracle Cloud Infrastructure resource. This is an optional parameter.
     * 
     */
    public Optional<Output<String>> availabilityDomain() {
        return Optional.ofNullable(this.availabilityDomain);
    }

    /**
     * The OCID of the tenancy from which the demand signal item was created.
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return The OCID of the tenancy from which the demand signal item was created.
     * 
     */
    public Output<String> compartmentId() {
        return this.compartmentId;
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
     * (Updatable) The quantity of the resource that you want to demand from OCI.
     * 
     */
    @Import(name="demandQuantity", required=true)
    private Output<String> demandQuantity;

    /**
     * @return (Updatable) The quantity of the resource that you want to demand from OCI.
     * 
     */
    public Output<String> demandQuantity() {
        return this.demandQuantity;
    }

    /**
     * The OCID of the correponding demand signal catalog resource.
     * 
     */
    @Import(name="demandSignalCatalogResourceId", required=true)
    private Output<String> demandSignalCatalogResourceId;

    /**
     * @return The OCID of the correponding demand signal catalog resource.
     * 
     */
    public Output<String> demandSignalCatalogResourceId() {
        return this.demandSignalCatalogResourceId;
    }

    /**
     * The OCID of the demand signal under which we need to create this item.
     * 
     */
    @Import(name="demandSignalId", required=true)
    private Output<String> demandSignalId;

    /**
     * @return The OCID of the demand signal under which we need to create this item.
     * 
     */
    public Output<String> demandSignalId() {
        return this.demandSignalId;
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
     * (Updatable) This field will serve as notes section for you. You can use this section to convey a message to Oracle Cloud Infrastructure regarding your resource request.
     * 
     * NOTE: The previous value gets overwritten with the new one for this once updated.
     * 
     */
    @Import(name="notes")
    private @Nullable Output<String> notes;

    /**
     * @return (Updatable) This field will serve as notes section for you. You can use this section to convey a message to Oracle Cloud Infrastructure regarding your resource request.
     * 
     * NOTE: The previous value gets overwritten with the new one for this once updated.
     * 
     */
    public Optional<Output<String>> notes() {
        return Optional.ofNullable(this.notes);
    }

    /**
     * (Updatable) The name of region for which you want to request the Oracle Cloud Infrastructure resource.
     * 
     */
    @Import(name="region", required=true)
    private Output<String> region;

    /**
     * @return (Updatable) The name of region for which you want to request the Oracle Cloud Infrastructure resource.
     * 
     */
    public Output<String> region() {
        return this.region;
    }

    /**
     * The type of request (DEMAND or RETURN) that you want to make for this demand signal item.
     * 
     */
    @Import(name="requestType", required=true)
    private Output<String> requestType;

    /**
     * @return The type of request (DEMAND or RETURN) that you want to make for this demand signal item.
     * 
     */
    public Output<String> requestType() {
        return this.requestType;
    }

    /**
     * (Updatable) A map of various properties associated with the Oracle Cloud Infrastructure resource.
     * 
     */
    @Import(name="resourceProperties", required=true)
    private Output<Map<String,String>> resourceProperties;

    /**
     * @return (Updatable) A map of various properties associated with the Oracle Cloud Infrastructure resource.
     * 
     */
    public Output<Map<String,String>> resourceProperties() {
        return this.resourceProperties;
    }

    /**
     * (Updatable) The OCID of the tenancy for which you want to request the Oracle Cloud Infrastructure resource for. This is an optional parameter.
     * 
     */
    @Import(name="targetCompartmentId")
    private @Nullable Output<String> targetCompartmentId;

    /**
     * @return (Updatable) The OCID of the tenancy for which you want to request the Oracle Cloud Infrastructure resource for. This is an optional parameter.
     * 
     */
    public Optional<Output<String>> targetCompartmentId() {
        return Optional.ofNullable(this.targetCompartmentId);
    }

    /**
     * (Updatable) the date before which you would ideally like the Oracle Cloud Infrastructure resource to be delivered to you.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    @Import(name="timeNeededBefore", required=true)
    private Output<String> timeNeededBefore;

    /**
     * @return (Updatable) the date before which you would ideally like the Oracle Cloud Infrastructure resource to be delivered to you.
     * 
     * ** IMPORTANT **
     * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
     * 
     */
    public Output<String> timeNeededBefore() {
        return this.timeNeededBefore;
    }

    private OccmDemandSignalItemArgs() {}

    private OccmDemandSignalItemArgs(OccmDemandSignalItemArgs $) {
        this.availabilityDomain = $.availabilityDomain;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.demandQuantity = $.demandQuantity;
        this.demandSignalCatalogResourceId = $.demandSignalCatalogResourceId;
        this.demandSignalId = $.demandSignalId;
        this.freeformTags = $.freeformTags;
        this.notes = $.notes;
        this.region = $.region;
        this.requestType = $.requestType;
        this.resourceProperties = $.resourceProperties;
        this.targetCompartmentId = $.targetCompartmentId;
        this.timeNeededBefore = $.timeNeededBefore;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(OccmDemandSignalItemArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private OccmDemandSignalItemArgs $;

        public Builder() {
            $ = new OccmDemandSignalItemArgs();
        }

        public Builder(OccmDemandSignalItemArgs defaults) {
            $ = new OccmDemandSignalItemArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param availabilityDomain (Updatable) The name of the availability domain for which you want to request the Oracle Cloud Infrastructure resource. This is an optional parameter.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(@Nullable Output<String> availabilityDomain) {
            $.availabilityDomain = availabilityDomain;
            return this;
        }

        /**
         * @param availabilityDomain (Updatable) The name of the availability domain for which you want to request the Oracle Cloud Infrastructure resource. This is an optional parameter.
         * 
         * @return builder
         * 
         */
        public Builder availabilityDomain(String availabilityDomain) {
            return availabilityDomain(Output.of(availabilityDomain));
        }

        /**
         * @param compartmentId The OCID of the tenancy from which the demand signal item was created.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The OCID of the tenancy from which the demand signal item was created.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
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
         * @param demandQuantity (Updatable) The quantity of the resource that you want to demand from OCI.
         * 
         * @return builder
         * 
         */
        public Builder demandQuantity(Output<String> demandQuantity) {
            $.demandQuantity = demandQuantity;
            return this;
        }

        /**
         * @param demandQuantity (Updatable) The quantity of the resource that you want to demand from OCI.
         * 
         * @return builder
         * 
         */
        public Builder demandQuantity(String demandQuantity) {
            return demandQuantity(Output.of(demandQuantity));
        }

        /**
         * @param demandSignalCatalogResourceId The OCID of the correponding demand signal catalog resource.
         * 
         * @return builder
         * 
         */
        public Builder demandSignalCatalogResourceId(Output<String> demandSignalCatalogResourceId) {
            $.demandSignalCatalogResourceId = demandSignalCatalogResourceId;
            return this;
        }

        /**
         * @param demandSignalCatalogResourceId The OCID of the correponding demand signal catalog resource.
         * 
         * @return builder
         * 
         */
        public Builder demandSignalCatalogResourceId(String demandSignalCatalogResourceId) {
            return demandSignalCatalogResourceId(Output.of(demandSignalCatalogResourceId));
        }

        /**
         * @param demandSignalId The OCID of the demand signal under which we need to create this item.
         * 
         * @return builder
         * 
         */
        public Builder demandSignalId(Output<String> demandSignalId) {
            $.demandSignalId = demandSignalId;
            return this;
        }

        /**
         * @param demandSignalId The OCID of the demand signal under which we need to create this item.
         * 
         * @return builder
         * 
         */
        public Builder demandSignalId(String demandSignalId) {
            return demandSignalId(Output.of(demandSignalId));
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
         * @param notes (Updatable) This field will serve as notes section for you. You can use this section to convey a message to Oracle Cloud Infrastructure regarding your resource request.
         * 
         * NOTE: The previous value gets overwritten with the new one for this once updated.
         * 
         * @return builder
         * 
         */
        public Builder notes(@Nullable Output<String> notes) {
            $.notes = notes;
            return this;
        }

        /**
         * @param notes (Updatable) This field will serve as notes section for you. You can use this section to convey a message to Oracle Cloud Infrastructure regarding your resource request.
         * 
         * NOTE: The previous value gets overwritten with the new one for this once updated.
         * 
         * @return builder
         * 
         */
        public Builder notes(String notes) {
            return notes(Output.of(notes));
        }

        /**
         * @param region (Updatable) The name of region for which you want to request the Oracle Cloud Infrastructure resource.
         * 
         * @return builder
         * 
         */
        public Builder region(Output<String> region) {
            $.region = region;
            return this;
        }

        /**
         * @param region (Updatable) The name of region for which you want to request the Oracle Cloud Infrastructure resource.
         * 
         * @return builder
         * 
         */
        public Builder region(String region) {
            return region(Output.of(region));
        }

        /**
         * @param requestType The type of request (DEMAND or RETURN) that you want to make for this demand signal item.
         * 
         * @return builder
         * 
         */
        public Builder requestType(Output<String> requestType) {
            $.requestType = requestType;
            return this;
        }

        /**
         * @param requestType The type of request (DEMAND or RETURN) that you want to make for this demand signal item.
         * 
         * @return builder
         * 
         */
        public Builder requestType(String requestType) {
            return requestType(Output.of(requestType));
        }

        /**
         * @param resourceProperties (Updatable) A map of various properties associated with the Oracle Cloud Infrastructure resource.
         * 
         * @return builder
         * 
         */
        public Builder resourceProperties(Output<Map<String,String>> resourceProperties) {
            $.resourceProperties = resourceProperties;
            return this;
        }

        /**
         * @param resourceProperties (Updatable) A map of various properties associated with the Oracle Cloud Infrastructure resource.
         * 
         * @return builder
         * 
         */
        public Builder resourceProperties(Map<String,String> resourceProperties) {
            return resourceProperties(Output.of(resourceProperties));
        }

        /**
         * @param targetCompartmentId (Updatable) The OCID of the tenancy for which you want to request the Oracle Cloud Infrastructure resource for. This is an optional parameter.
         * 
         * @return builder
         * 
         */
        public Builder targetCompartmentId(@Nullable Output<String> targetCompartmentId) {
            $.targetCompartmentId = targetCompartmentId;
            return this;
        }

        /**
         * @param targetCompartmentId (Updatable) The OCID of the tenancy for which you want to request the Oracle Cloud Infrastructure resource for. This is an optional parameter.
         * 
         * @return builder
         * 
         */
        public Builder targetCompartmentId(String targetCompartmentId) {
            return targetCompartmentId(Output.of(targetCompartmentId));
        }

        /**
         * @param timeNeededBefore (Updatable) the date before which you would ideally like the Oracle Cloud Infrastructure resource to be delivered to you.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder timeNeededBefore(Output<String> timeNeededBefore) {
            $.timeNeededBefore = timeNeededBefore;
            return this;
        }

        /**
         * @param timeNeededBefore (Updatable) the date before which you would ideally like the Oracle Cloud Infrastructure resource to be delivered to you.
         * 
         * ** IMPORTANT **
         * Any change to a property that does not support update will force the destruction and recreation of the resource with the new property values
         * 
         * @return builder
         * 
         */
        public Builder timeNeededBefore(String timeNeededBefore) {
            return timeNeededBefore(Output.of(timeNeededBefore));
        }

        public OccmDemandSignalItemArgs build() {
            if ($.compartmentId == null) {
                throw new MissingRequiredPropertyException("OccmDemandSignalItemArgs", "compartmentId");
            }
            if ($.demandQuantity == null) {
                throw new MissingRequiredPropertyException("OccmDemandSignalItemArgs", "demandQuantity");
            }
            if ($.demandSignalCatalogResourceId == null) {
                throw new MissingRequiredPropertyException("OccmDemandSignalItemArgs", "demandSignalCatalogResourceId");
            }
            if ($.demandSignalId == null) {
                throw new MissingRequiredPropertyException("OccmDemandSignalItemArgs", "demandSignalId");
            }
            if ($.region == null) {
                throw new MissingRequiredPropertyException("OccmDemandSignalItemArgs", "region");
            }
            if ($.requestType == null) {
                throw new MissingRequiredPropertyException("OccmDemandSignalItemArgs", "requestType");
            }
            if ($.resourceProperties == null) {
                throw new MissingRequiredPropertyException("OccmDemandSignalItemArgs", "resourceProperties");
            }
            if ($.timeNeededBefore == null) {
                throw new MissingRequiredPropertyException("OccmDemandSignalItemArgs", "timeNeededBefore");
            }
            return $;
        }
    }

}
