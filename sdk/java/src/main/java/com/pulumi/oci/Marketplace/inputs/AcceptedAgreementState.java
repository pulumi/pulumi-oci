// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.inputs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class AcceptedAgreementState extends com.pulumi.resources.ResourceArgs {

    public static final AcceptedAgreementState Empty = new AcceptedAgreementState();

    /**
     * The agreement to accept.
     * 
     */
    @Import(name="agreementId")
    private @Nullable Output<String> agreementId;

    /**
     * @return The agreement to accept.
     * 
     */
    public Optional<Output<String>> agreementId() {
        return Optional.ofNullable(this.agreementId);
    }

    /**
     * The unique identifier for the compartment where the agreement will be accepted.
     * 
     */
    @Import(name="compartmentId")
    private @Nullable Output<String> compartmentId;

    /**
     * @return The unique identifier for the compartment where the agreement will be accepted.
     * 
     */
    public Optional<Output<String>> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }

    /**
     * (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    @Import(name="definedTags")
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) A display name for the accepted agreement.
     * 
     */
    @Import(name="displayName")
    private @Nullable Output<String> displayName;

    /**
     * @return (Updatable) A display name for the accepted agreement.
     * 
     */
    public Optional<Output<String>> displayName() {
        return Optional.ofNullable(this.displayName);
    }

    /**
     * (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    @Import(name="freeformTags")
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * The unique identifier for the listing associated with the agreement.
     * 
     */
    @Import(name="listingId")
    private @Nullable Output<String> listingId;

    /**
     * @return The unique identifier for the listing associated with the agreement.
     * 
     */
    public Optional<Output<String>> listingId() {
        return Optional.ofNullable(this.listingId);
    }

    /**
     * The package version associated with the agreement.
     * 
     */
    @Import(name="packageVersion")
    private @Nullable Output<String> packageVersion;

    /**
     * @return The package version associated with the agreement.
     * 
     */
    public Optional<Output<String>> packageVersion() {
        return Optional.ofNullable(this.packageVersion);
    }

    /**
     * A signature generated for the listing package agreements that you can retrieve with [GetAgreement](https://docs.cloud.oracle.com/iaas/api/#/en/marketplace/20181001/Agreement/GetAgreement).
     * 
     */
    @Import(name="signature")
    private @Nullable Output<String> signature;

    /**
     * @return A signature generated for the listing package agreements that you can retrieve with [GetAgreement](https://docs.cloud.oracle.com/iaas/api/#/en/marketplace/20181001/Agreement/GetAgreement).
     * 
     */
    public Optional<Output<String>> signature() {
        return Optional.ofNullable(this.signature);
    }

    /**
     * The time the agreement was accepted.
     * 
     */
    @Import(name="timeAccepted")
    private @Nullable Output<String> timeAccepted;

    /**
     * @return The time the agreement was accepted.
     * 
     */
    public Optional<Output<String>> timeAccepted() {
        return Optional.ofNullable(this.timeAccepted);
    }

    private AcceptedAgreementState() {}

    private AcceptedAgreementState(AcceptedAgreementState $) {
        this.agreementId = $.agreementId;
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.listingId = $.listingId;
        this.packageVersion = $.packageVersion;
        this.signature = $.signature;
        this.timeAccepted = $.timeAccepted;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(AcceptedAgreementState defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private AcceptedAgreementState $;

        public Builder() {
            $ = new AcceptedAgreementState();
        }

        public Builder(AcceptedAgreementState defaults) {
            $ = new AcceptedAgreementState(Objects.requireNonNull(defaults));
        }

        /**
         * @param agreementId The agreement to accept.
         * 
         * @return builder
         * 
         */
        public Builder agreementId(@Nullable Output<String> agreementId) {
            $.agreementId = agreementId;
            return this;
        }

        /**
         * @param agreementId The agreement to accept.
         * 
         * @return builder
         * 
         */
        public Builder agreementId(String agreementId) {
            return agreementId(Output.of(agreementId));
        }

        /**
         * @param compartmentId The unique identifier for the compartment where the agreement will be accepted.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(@Nullable Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId The unique identifier for the compartment where the agreement will be accepted.
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(String compartmentId) {
            return compartmentId(Output.of(compartmentId));
        }

        /**
         * @param definedTags (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) The defined tags associated with this resource, if any. Each key is predefined and scoped to namespaces. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Operations.CostCenter&#34;: &#34;42&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) A display name for the accepted agreement.
         * 
         * @return builder
         * 
         */
        public Builder displayName(@Nullable Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) A display name for the accepted agreement.
         * 
         * @return builder
         * 
         */
        public Builder displayName(String displayName) {
            return displayName(Output.of(displayName));
        }

        /**
         * @param freeformTags (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) The freeform tags associated with this resource, if any. Each tag is a simple key-value pair with no predefined name, type, or namespace. For more information, see [Resource Tags](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/resourcetags.htm). Example: `{&#34;Department&#34;: &#34;Finance&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param listingId The unique identifier for the listing associated with the agreement.
         * 
         * @return builder
         * 
         */
        public Builder listingId(@Nullable Output<String> listingId) {
            $.listingId = listingId;
            return this;
        }

        /**
         * @param listingId The unique identifier for the listing associated with the agreement.
         * 
         * @return builder
         * 
         */
        public Builder listingId(String listingId) {
            return listingId(Output.of(listingId));
        }

        /**
         * @param packageVersion The package version associated with the agreement.
         * 
         * @return builder
         * 
         */
        public Builder packageVersion(@Nullable Output<String> packageVersion) {
            $.packageVersion = packageVersion;
            return this;
        }

        /**
         * @param packageVersion The package version associated with the agreement.
         * 
         * @return builder
         * 
         */
        public Builder packageVersion(String packageVersion) {
            return packageVersion(Output.of(packageVersion));
        }

        /**
         * @param signature A signature generated for the listing package agreements that you can retrieve with [GetAgreement](https://docs.cloud.oracle.com/iaas/api/#/en/marketplace/20181001/Agreement/GetAgreement).
         * 
         * @return builder
         * 
         */
        public Builder signature(@Nullable Output<String> signature) {
            $.signature = signature;
            return this;
        }

        /**
         * @param signature A signature generated for the listing package agreements that you can retrieve with [GetAgreement](https://docs.cloud.oracle.com/iaas/api/#/en/marketplace/20181001/Agreement/GetAgreement).
         * 
         * @return builder
         * 
         */
        public Builder signature(String signature) {
            return signature(Output.of(signature));
        }

        /**
         * @param timeAccepted The time the agreement was accepted.
         * 
         * @return builder
         * 
         */
        public Builder timeAccepted(@Nullable Output<String> timeAccepted) {
            $.timeAccepted = timeAccepted;
            return this;
        }

        /**
         * @param timeAccepted The time the agreement was accepted.
         * 
         * @return builder
         * 
         */
        public Builder timeAccepted(String timeAccepted) {
            return timeAccepted(Output.of(timeAccepted));
        }

        public AcceptedAgreementState build() {
            return $;
        }
    }

}