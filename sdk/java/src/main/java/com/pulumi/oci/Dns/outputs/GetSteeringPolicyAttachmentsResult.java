// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Dns.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Dns.outputs.GetSteeringPolicyAttachmentsFilter;
import com.pulumi.oci.Dns.outputs.GetSteeringPolicyAttachmentsSteeringPolicyAttachment;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSteeringPolicyAttachmentsResult {
    /**
     * @return The OCID of the compartment containing the steering policy attachment.
     * 
     */
    private String compartmentId;
    /**
     * @return A user-friendly name for the steering policy attachment. Does not have to be unique and can be changed. Avoid entering confidential information.
     * 
     */
    private @Nullable String displayName;
    private @Nullable String domain;
    private @Nullable String domainContains;
    private @Nullable List<GetSteeringPolicyAttachmentsFilter> filters;
    /**
     * @return The OCID of the resource.
     * 
     */
    private @Nullable String id;
    /**
     * @return The current state of the resource.
     * 
     */
    private @Nullable String state;
    /**
     * @return The list of steering_policy_attachments.
     * 
     */
    private List<GetSteeringPolicyAttachmentsSteeringPolicyAttachment> steeringPolicyAttachments;
    /**
     * @return The OCID of the attached steering policy.
     * 
     */
    private @Nullable String steeringPolicyId;
    private @Nullable String timeCreatedGreaterThanOrEqualTo;
    private @Nullable String timeCreatedLessThan;
    /**
     * @return The OCID of the attached zone.
     * 
     */
    private @Nullable String zoneId;

    private GetSteeringPolicyAttachmentsResult() {}
    /**
     * @return The OCID of the compartment containing the steering policy attachment.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return A user-friendly name for the steering policy attachment. Does not have to be unique and can be changed. Avoid entering confidential information.
     * 
     */
    public Optional<String> displayName() {
        return Optional.ofNullable(this.displayName);
    }
    public Optional<String> domain() {
        return Optional.ofNullable(this.domain);
    }
    public Optional<String> domainContains() {
        return Optional.ofNullable(this.domainContains);
    }
    public List<GetSteeringPolicyAttachmentsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The OCID of the resource.
     * 
     */
    public Optional<String> id() {
        return Optional.ofNullable(this.id);
    }
    /**
     * @return The current state of the resource.
     * 
     */
    public Optional<String> state() {
        return Optional.ofNullable(this.state);
    }
    /**
     * @return The list of steering_policy_attachments.
     * 
     */
    public List<GetSteeringPolicyAttachmentsSteeringPolicyAttachment> steeringPolicyAttachments() {
        return this.steeringPolicyAttachments;
    }
    /**
     * @return The OCID of the attached steering policy.
     * 
     */
    public Optional<String> steeringPolicyId() {
        return Optional.ofNullable(this.steeringPolicyId);
    }
    public Optional<String> timeCreatedGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeCreatedGreaterThanOrEqualTo);
    }
    public Optional<String> timeCreatedLessThan() {
        return Optional.ofNullable(this.timeCreatedLessThan);
    }
    /**
     * @return The OCID of the attached zone.
     * 
     */
    public Optional<String> zoneId() {
        return Optional.ofNullable(this.zoneId);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSteeringPolicyAttachmentsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String compartmentId;
        private @Nullable String displayName;
        private @Nullable String domain;
        private @Nullable String domainContains;
        private @Nullable List<GetSteeringPolicyAttachmentsFilter> filters;
        private @Nullable String id;
        private @Nullable String state;
        private List<GetSteeringPolicyAttachmentsSteeringPolicyAttachment> steeringPolicyAttachments;
        private @Nullable String steeringPolicyId;
        private @Nullable String timeCreatedGreaterThanOrEqualTo;
        private @Nullable String timeCreatedLessThan;
        private @Nullable String zoneId;
        public Builder() {}
        public Builder(GetSteeringPolicyAttachmentsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.displayName = defaults.displayName;
    	      this.domain = defaults.domain;
    	      this.domainContains = defaults.domainContains;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.state = defaults.state;
    	      this.steeringPolicyAttachments = defaults.steeringPolicyAttachments;
    	      this.steeringPolicyId = defaults.steeringPolicyId;
    	      this.timeCreatedGreaterThanOrEqualTo = defaults.timeCreatedGreaterThanOrEqualTo;
    	      this.timeCreatedLessThan = defaults.timeCreatedLessThan;
    	      this.zoneId = defaults.zoneId;
        }

        @CustomType.Setter
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        @CustomType.Setter
        public Builder displayName(@Nullable String displayName) {
            this.displayName = displayName;
            return this;
        }
        @CustomType.Setter
        public Builder domain(@Nullable String domain) {
            this.domain = domain;
            return this;
        }
        @CustomType.Setter
        public Builder domainContains(@Nullable String domainContains) {
            this.domainContains = domainContains;
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetSteeringPolicyAttachmentsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetSteeringPolicyAttachmentsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(@Nullable String id) {
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder state(@Nullable String state) {
            this.state = state;
            return this;
        }
        @CustomType.Setter
        public Builder steeringPolicyAttachments(List<GetSteeringPolicyAttachmentsSteeringPolicyAttachment> steeringPolicyAttachments) {
            this.steeringPolicyAttachments = Objects.requireNonNull(steeringPolicyAttachments);
            return this;
        }
        public Builder steeringPolicyAttachments(GetSteeringPolicyAttachmentsSteeringPolicyAttachment... steeringPolicyAttachments) {
            return steeringPolicyAttachments(List.of(steeringPolicyAttachments));
        }
        @CustomType.Setter
        public Builder steeringPolicyId(@Nullable String steeringPolicyId) {
            this.steeringPolicyId = steeringPolicyId;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreatedGreaterThanOrEqualTo(@Nullable String timeCreatedGreaterThanOrEqualTo) {
            this.timeCreatedGreaterThanOrEqualTo = timeCreatedGreaterThanOrEqualTo;
            return this;
        }
        @CustomType.Setter
        public Builder timeCreatedLessThan(@Nullable String timeCreatedLessThan) {
            this.timeCreatedLessThan = timeCreatedLessThan;
            return this;
        }
        @CustomType.Setter
        public Builder zoneId(@Nullable String zoneId) {
            this.zoneId = zoneId;
            return this;
        }
        public GetSteeringPolicyAttachmentsResult build() {
            final var o = new GetSteeringPolicyAttachmentsResult();
            o.compartmentId = compartmentId;
            o.displayName = displayName;
            o.domain = domain;
            o.domainContains = domainContains;
            o.filters = filters;
            o.id = id;
            o.state = state;
            o.steeringPolicyAttachments = steeringPolicyAttachments;
            o.steeringPolicyId = steeringPolicyId;
            o.timeCreatedGreaterThanOrEqualTo = timeCreatedGreaterThanOrEqualTo;
            o.timeCreatedLessThan = timeCreatedLessThan;
            o.zoneId = zoneId;
            return o;
        }
    }
}