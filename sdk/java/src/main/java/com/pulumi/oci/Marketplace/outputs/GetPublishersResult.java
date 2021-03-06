// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Marketplace.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Marketplace.outputs.GetPublishersFilter;
import com.pulumi.oci.Marketplace.outputs.GetPublishersPublisher;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetPublishersResult {
    private final @Nullable String compartmentId;
    private final @Nullable List<GetPublishersFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private final String id;
    private final @Nullable String publisherId;
    /**
     * @return The list of publishers.
     * 
     */
    private final List<GetPublishersPublisher> publishers;

    @CustomType.Constructor
    private GetPublishersResult(
        @CustomType.Parameter("compartmentId") @Nullable String compartmentId,
        @CustomType.Parameter("filters") @Nullable List<GetPublishersFilter> filters,
        @CustomType.Parameter("id") String id,
        @CustomType.Parameter("publisherId") @Nullable String publisherId,
        @CustomType.Parameter("publishers") List<GetPublishersPublisher> publishers) {
        this.compartmentId = compartmentId;
        this.filters = filters;
        this.id = id;
        this.publisherId = publisherId;
        this.publishers = publishers;
    }

    public Optional<String> compartmentId() {
        return Optional.ofNullable(this.compartmentId);
    }
    public List<GetPublishersFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> publisherId() {
        return Optional.ofNullable(this.publisherId);
    }
    /**
     * @return The list of publishers.
     * 
     */
    public List<GetPublishersPublisher> publishers() {
        return this.publishers;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetPublishersResult defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private @Nullable String compartmentId;
        private @Nullable List<GetPublishersFilter> filters;
        private String id;
        private @Nullable String publisherId;
        private List<GetPublishersPublisher> publishers;

        public Builder() {
    	      // Empty
        }

        public Builder(GetPublishersResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.compartmentId = defaults.compartmentId;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.publisherId = defaults.publisherId;
    	      this.publishers = defaults.publishers;
        }

        public Builder compartmentId(@Nullable String compartmentId) {
            this.compartmentId = compartmentId;
            return this;
        }
        public Builder filters(@Nullable List<GetPublishersFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetPublishersFilter... filters) {
            return filters(List.of(filters));
        }
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        public Builder publisherId(@Nullable String publisherId) {
            this.publisherId = publisherId;
            return this;
        }
        public Builder publishers(List<GetPublishersPublisher> publishers) {
            this.publishers = Objects.requireNonNull(publishers);
            return this;
        }
        public Builder publishers(GetPublishersPublisher... publishers) {
            return publishers(List.of(publishers));
        }        public GetPublishersResult build() {
            return new GetPublishersResult(compartmentId, filters, id, publisherId, publishers);
        }
    }
}
