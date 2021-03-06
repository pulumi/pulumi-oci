// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.OsubSubscription.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.OsubSubscription.outputs.GetCommitmentsCommitment;
import com.pulumi.oci.OsubSubscription.outputs.GetCommitmentsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetCommitmentsResult {
    /**
     * @return The list of commitments.
     * 
     */
    private final List<GetCommitmentsCommitment> commitments;
    private final String compartmentId;
    private final @Nullable List<GetCommitmentsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final String subscribedServiceId;
    private final @Nullable String xOneGatewaySubscriptionId;
    private final @Nullable String xOneOriginRegion;

    @CustomType.Constructor
    private GetCommitmentsResult(
        @CustomType.Parameter("commitments") List<GetCommitmentsCommitment> commitments,
        @CustomType.Parameter("compartmentId") String compartmentId,
        @CustomType.Parameter("filters") @Nullable List<GetCommitmentsFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("subscribedServiceId") String subscribedServiceId,
        @CustomType.Parameter("xOneGatewaySubscriptionId") @Nullable String xOneGatewaySubscriptionId,
        @CustomType.Parameter("xOneOriginRegion") @Nullable String xOneOriginRegion) {
        this.commitments = commitments;
        this.compartmentId = compartmentId;
        this.filters = filters;
        this.id = id;
        this.subscribedServiceId = subscribedServiceId;
        this.xOneGatewaySubscriptionId = xOneGatewaySubscriptionId;
        this.xOneOriginRegion = xOneOriginRegion;
    }

    /**
     * @return The list of commitments.
     * 
     */
    public List<GetCommitmentsCommitment> commitments() {
        return this.commitments;
    }
    public String compartmentId() {
        return this.compartmentId;
    }
    public List<GetCommitmentsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public String subscribedServiceId() {
        return this.subscribedServiceId;
    }
    public Optional<String> xOneGatewaySubscriptionId() {
        return Optional.ofNullable(this.xOneGatewaySubscriptionId);
    }
    public Optional<String> xOneOriginRegion() {
        return Optional.ofNullable(this.xOneOriginRegion);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetCommitmentsResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<GetCommitmentsCommitment> commitments;
        private String compartmentId;
        private @Nullable List<GetCommitmentsFilter> filters;
        private String id;
        private String subscribedServiceId;
        private @Nullable String xOneGatewaySubscriptionId;
        private @Nullable String xOneOriginRegion;

        public Builder() {
    	      // Empty
        }

        public Builder(GetCommitmentsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.commitments = defaults.commitments;
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.subscribedServiceId = defaults.subscribedServiceId;
    	      this.xOneGatewaySubscriptionId = defaults.xOneGatewaySubscriptionId;
    	      this.xOneOriginRegion = defaults.xOneOriginRegion;
        }

        public Builder commitments(List<GetCommitmentsCommitment> commitments) {
            this.commitments = Objects.requireNonNull(commitments);
            return this;
        }
        public Builder commitments(GetCommitmentsCommitment... commitments) {
            return commitments(List.of(commitments));
        }
        public Builder compartmentId(String compartmentId) {
            this.compartmentId = Objects.requireNonNull(compartmentId);
            return this;
        }
        public Builder filters(@Nullable List<GetCommitmentsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetCommitmentsFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder subscribedServiceId(String subscribedServiceId) {
            this.subscribedServiceId = Objects.requireNonNull(subscribedServiceId);
            return this;
        }
        public Builder xOneGatewaySubscriptionId(@Nullable String xOneGatewaySubscriptionId) {
            this.xOneGatewaySubscriptionId = xOneGatewaySubscriptionId;
            return this;
        }
        public Builder xOneOriginRegion(@Nullable String xOneOriginRegion) {
            this.xOneOriginRegion = xOneOriginRegion;
            return this;
        }        public GetCommitmentsResult build() {
            return new GetCommitmentsResult(commitments, compartmentId, filters, id, subscribedServiceId, xOneGatewaySubscriptionId, xOneOriginRegion);
        }
    }
}
