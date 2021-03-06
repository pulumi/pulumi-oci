// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Email.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Email.outputs.GetSuppressionsFilter;
import com.pulumi.oci.Email.outputs.GetSuppressionsSuppression;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetSuppressionsResult {
    /**
     * @return The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
     * 
     */
    private final String compartmentId;
    /**
     * @return The email address of the suppression.
     * 
     */
    private final @Nullable String emailAddress;
    private final @Nullable List<GetSuppressionsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    /**
     * @return The list of suppressions.
     * 
     */
    private final List<GetSuppressionsSuppression> suppressions;
    private final @Nullable String timeCreatedGreaterThanOrEqualTo;
    private final @Nullable String timeCreatedLessThan;

    @CustomType.Constructor
    private GetSuppressionsResult(
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("emailAddress") @Nullable String emailAddress,
        @CustomType.Parameter("filters") @Nullable List<GetSuppressionsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("suppressions") List<GetSuppressionsSuppression> suppressions,
        @CustomType.Parameter("timeCreatedGreaterThanOrEqualTo") @Nullable String timeCreatedGreaterThanOrEqualTo,
        @CustomType.Parameter("timeCreatedLessThan") @Nullable String timeCreatedLessThan) {
        this.compartmentId = compartmentId;
        this.emailAddress = emailAddress;
        this.filters = filters;
        this.id = id;
        this.suppressions = suppressions;
        this.timeCreatedGreaterThanOrEqualTo = timeCreatedGreaterThanOrEqualTo;
        this.timeCreatedLessThan = timeCreatedLessThan;
    }

    /**
     * @return The OCID of the compartment to contain the suppression. Since suppressions are at the customer level, this must be the tenancy OCID.
     * 
     */
    public String compartmentId() {
        return this.compartmentId;
    }
    /**
     * @return The email address of the suppression.
     * 
     */
    public Optional<String> emailAddress() {
        return Optional.ofNullable(this.emailAddress);
    }
    public List<GetSuppressionsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The list of suppressions.
     * 
     */
    public List<GetSuppressionsSuppression> suppressions() {
        return this.suppressions;
    }
    public Optional<String> timeCreatedGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeCreatedGreaterThanOrEqualTo);
    }
    public Optional<String> timeCreatedLessThan() {
        return Optional.ofNullable(this.timeCreatedLessThan);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetSuppressionsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private String compartmentId;
        private @Nullable String emailAddress;
        private @Nullable List<GetSuppressionsFilter> filters;
        private String id;
        private List<GetSuppressionsSuppression> suppressions;
        private @Nullable String timeCreatedGreaterThanOrEqualTo;
        private @Nullable String timeCreatedLessThan;

        public Builder() {
    	      // Empty
        }

        public Builder(GetSuppressionsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.emailAddress = defaults.emailAddress;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.suppressions = defaults.suppressions;
    	      this.timeCreatedGreaterThanOrEqualTo = defaults.timeCreatedGreaterThanOrEqualTo;
    	      this.timeCreatedLessThan = defaults.timeCreatedLessThan;
        }

        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder emailAddress(@Nullable String emailAddress) {
            this.emailAddress = emailAddress;
            return this;
        }
        public Builder filters(@Nullable List<GetSuppressionsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetSuppressionsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder suppressions(List<GetSuppressionsSuppression> suppressions) {
            this.suppressions = Objects.requireNonNull(suppressions);
            return this;
        }
        public Builder suppressions(GetSuppressionsSuppression... suppressions) {
            return suppressions(List.of(suppressions));
        }
        public Builder timeCreatedGreaterThanOrEqualTo(@Nullable String timeCreatedGreaterThanOrEqualTo) {
            this.timeCreatedGreaterThanOrEqualTo = timeCreatedGreaterThanOrEqualTo;
            return this;
        }
        public Builder timeCreatedLessThan(@Nullable String timeCreatedLessThan) {
            this.timeCreatedLessThan = timeCreatedLessThan;
            return this;
        }        public GetSuppressionsResult build() {
            return new GetSuppressionsResult(compartmentId, emailAddress, filters, id, suppressions, timeCreatedGreaterThanOrEqualTo, timeCreatedLessThan);
        }
    }
}
