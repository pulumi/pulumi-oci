// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Vbs;

import com.pulumi.core.Output;
import com.pulumi.core.annotations.Import;
import java.lang.Boolean;
import java.lang.Object;
import java.lang.String;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;


public final class InstVbsInstanceArgs extends com.pulumi.resources.ResourceArgs {

    public static final InstVbsInstanceArgs Empty = new InstVbsInstanceArgs();

    /**
     * (Updatable) Compartment Identifier. It can only be the root compartment
     * 
     */
    @Import(name="compartmentId", required=true)
    private Output<String> compartmentId;

    /**
     * @return (Updatable) Compartment Identifier. It can only be the root compartment
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
    private @Nullable Output<Map<String,Object>> definedTags;

    /**
     * @return (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> definedTags() {
        return Optional.ofNullable(this.definedTags);
    }

    /**
     * (Updatable) Display Name
     * 
     */
    @Import(name="displayName", required=true)
    private Output<String> displayName;

    /**
     * @return (Updatable) Display Name
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
    private @Nullable Output<Map<String,Object>> freeformTags;

    /**
     * @return (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
     * 
     */
    public Optional<Output<Map<String,Object>>> freeformTags() {
        return Optional.ofNullable(this.freeformTags);
    }

    /**
     * IDCS personal acceess token identifying IDCS user and stripe for the VBS service
     * 
     */
    @Import(name="idcsAccessToken")
    private @Nullable Output<String> idcsAccessToken;

    /**
     * @return IDCS personal acceess token identifying IDCS user and stripe for the VBS service
     * 
     */
    public Optional<Output<String>> idcsAccessToken() {
        return Optional.ofNullable(this.idcsAccessToken);
    }

    /**
     * (Updatable) Whether VBS is authorized to create and use resources in the customer tenancy
     * 
     */
    @Import(name="isResourceUsageAgreementGranted")
    private @Nullable Output<Boolean> isResourceUsageAgreementGranted;

    /**
     * @return (Updatable) Whether VBS is authorized to create and use resources in the customer tenancy
     * 
     */
    public Optional<Output<Boolean>> isResourceUsageAgreementGranted() {
        return Optional.ofNullable(this.isResourceUsageAgreementGranted);
    }

    /**
     * Service Instance Name
     * 
     */
    @Import(name="name")
    private @Nullable Output<String> name;

    /**
     * @return Service Instance Name
     * 
     */
    public Optional<Output<String>> name() {
        return Optional.ofNullable(this.name);
    }

    /**
     * (Updatable) Compartment where VBS may create additional resources for the service instance
     * 
     */
    @Import(name="resourceCompartmentId")
    private @Nullable Output<String> resourceCompartmentId;

    /**
     * @return (Updatable) Compartment where VBS may create additional resources for the service instance
     * 
     */
    public Optional<Output<String>> resourceCompartmentId() {
        return Optional.ofNullable(this.resourceCompartmentId);
    }

    private InstVbsInstanceArgs() {}

    private InstVbsInstanceArgs(InstVbsInstanceArgs $) {
        this.compartmentId = $.compartmentId;
        this.definedTags = $.definedTags;
        this.displayName = $.displayName;
        this.freeformTags = $.freeformTags;
        this.idcsAccessToken = $.idcsAccessToken;
        this.isResourceUsageAgreementGranted = $.isResourceUsageAgreementGranted;
        this.name = $.name;
        this.resourceCompartmentId = $.resourceCompartmentId;
    }

    public static Builder builder() {
        return new Builder();
    }
    public static Builder builder(InstVbsInstanceArgs defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private InstVbsInstanceArgs $;

        public Builder() {
            $ = new InstVbsInstanceArgs();
        }

        public Builder(InstVbsInstanceArgs defaults) {
            $ = new InstVbsInstanceArgs(Objects.requireNonNull(defaults));
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier. It can only be the root compartment
         * 
         * @return builder
         * 
         */
        public Builder compartmentId(Output<String> compartmentId) {
            $.compartmentId = compartmentId;
            return this;
        }

        /**
         * @param compartmentId (Updatable) Compartment Identifier. It can only be the root compartment
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
        public Builder definedTags(@Nullable Output<Map<String,Object>> definedTags) {
            $.definedTags = definedTags;
            return this;
        }

        /**
         * @param definedTags (Updatable) Defined tags for this resource. Each key is predefined and scoped to a namespace. Example: `{&#34;foo-namespace.bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder definedTags(Map<String,Object> definedTags) {
            return definedTags(Output.of(definedTags));
        }

        /**
         * @param displayName (Updatable) Display Name
         * 
         * @return builder
         * 
         */
        public Builder displayName(Output<String> displayName) {
            $.displayName = displayName;
            return this;
        }

        /**
         * @param displayName (Updatable) Display Name
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
        public Builder freeformTags(@Nullable Output<Map<String,Object>> freeformTags) {
            $.freeformTags = freeformTags;
            return this;
        }

        /**
         * @param freeformTags (Updatable) Simple key-value pair that is applied without any predefined name, type or scope. Exists for cross-compatibility only. Example: `{&#34;bar-key&#34;: &#34;value&#34;}`
         * 
         * @return builder
         * 
         */
        public Builder freeformTags(Map<String,Object> freeformTags) {
            return freeformTags(Output.of(freeformTags));
        }

        /**
         * @param idcsAccessToken IDCS personal acceess token identifying IDCS user and stripe for the VBS service
         * 
         * @return builder
         * 
         */
        public Builder idcsAccessToken(@Nullable Output<String> idcsAccessToken) {
            $.idcsAccessToken = idcsAccessToken;
            return this;
        }

        /**
         * @param idcsAccessToken IDCS personal acceess token identifying IDCS user and stripe for the VBS service
         * 
         * @return builder
         * 
         */
        public Builder idcsAccessToken(String idcsAccessToken) {
            return idcsAccessToken(Output.of(idcsAccessToken));
        }

        /**
         * @param isResourceUsageAgreementGranted (Updatable) Whether VBS is authorized to create and use resources in the customer tenancy
         * 
         * @return builder
         * 
         */
        public Builder isResourceUsageAgreementGranted(@Nullable Output<Boolean> isResourceUsageAgreementGranted) {
            $.isResourceUsageAgreementGranted = isResourceUsageAgreementGranted;
            return this;
        }

        /**
         * @param isResourceUsageAgreementGranted (Updatable) Whether VBS is authorized to create and use resources in the customer tenancy
         * 
         * @return builder
         * 
         */
        public Builder isResourceUsageAgreementGranted(Boolean isResourceUsageAgreementGranted) {
            return isResourceUsageAgreementGranted(Output.of(isResourceUsageAgreementGranted));
        }

        /**
         * @param name Service Instance Name
         * 
         * @return builder
         * 
         */
        public Builder name(@Nullable Output<String> name) {
            $.name = name;
            return this;
        }

        /**
         * @param name Service Instance Name
         * 
         * @return builder
         * 
         */
        public Builder name(String name) {
            return name(Output.of(name));
        }

        /**
         * @param resourceCompartmentId (Updatable) Compartment where VBS may create additional resources for the service instance
         * 
         * @return builder
         * 
         */
        public Builder resourceCompartmentId(@Nullable Output<String> resourceCompartmentId) {
            $.resourceCompartmentId = resourceCompartmentId;
            return this;
        }

        /**
         * @param resourceCompartmentId (Updatable) Compartment where VBS may create additional resources for the service instance
         * 
         * @return builder
         * 
         */
        public Builder resourceCompartmentId(String resourceCompartmentId) {
            return resourceCompartmentId(Output.of(resourceCompartmentId));
        }

        public InstVbsInstanceArgs build() {
            $.compartmentId = Objects.requireNonNull($.compartmentId, "expected parameter 'compartmentId' to be non-null");
            $.displayName = Objects.requireNonNull($.displayName, "expected parameter 'displayName' to be non-null");
            return $;
        }
    }

}