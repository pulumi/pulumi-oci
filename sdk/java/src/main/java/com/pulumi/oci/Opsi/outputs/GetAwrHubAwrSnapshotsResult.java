// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Opsi.outputs.GetAwrHubAwrSnapshotsAwrSnapshotCollection;
import com.pulumi.oci.Opsi.outputs.GetAwrHubAwrSnapshotsFilter;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetAwrHubAwrSnapshotsResult {
    private String awrHubId;
    /**
     * @return The list of awr_snapshot_collection.
     * 
     */
    private List<GetAwrHubAwrSnapshotsAwrSnapshotCollection> awrSnapshotCollections;
    private String awrSourceDatabaseIdentifier;
    private @Nullable List<GetAwrHubAwrSnapshotsFilter> filters;
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    private @Nullable String timeGreaterThanOrEqualTo;
    private @Nullable String timeLessThanOrEqualTo;

    private GetAwrHubAwrSnapshotsResult() {}
    public String awrHubId() {
        return this.awrHubId;
    }
    /**
     * @return The list of awr_snapshot_collection.
     * 
     */
    public List<GetAwrHubAwrSnapshotsAwrSnapshotCollection> awrSnapshotCollections() {
        return this.awrSnapshotCollections;
    }
    public String awrSourceDatabaseIdentifier() {
        return this.awrSourceDatabaseIdentifier;
    }
    public List<GetAwrHubAwrSnapshotsFilter> filters() {
        return this.filters == null ? List.of() : this.filters;
    }
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    public Optional<String> timeGreaterThanOrEqualTo() {
        return Optional.ofNullable(this.timeGreaterThanOrEqualTo);
    }
    public Optional<String> timeLessThanOrEqualTo() {
        return Optional.ofNullable(this.timeLessThanOrEqualTo);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAwrHubAwrSnapshotsResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String awrHubId;
        private List<GetAwrHubAwrSnapshotsAwrSnapshotCollection> awrSnapshotCollections;
        private String awrSourceDatabaseIdentifier;
        private @Nullable List<GetAwrHubAwrSnapshotsFilter> filters;
        private String id;
        private @Nullable String timeGreaterThanOrEqualTo;
        private @Nullable String timeLessThanOrEqualTo;
        public Builder() {}
        public Builder(GetAwrHubAwrSnapshotsResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.awrHubId = defaults.awrHubId;
    	      this.awrSnapshotCollections = defaults.awrSnapshotCollections;
    	      this.awrSourceDatabaseIdentifier = defaults.awrSourceDatabaseIdentifier;
    	      this.filters = defaults.filters;
    	      this.id = defaults.id;
    	      this.timeGreaterThanOrEqualTo = defaults.timeGreaterThanOrEqualTo;
    	      this.timeLessThanOrEqualTo = defaults.timeLessThanOrEqualTo;
        }

        @CustomType.Setter
        public Builder awrHubId(String awrHubId) {
            this.awrHubId = Objects.requireNonNull(awrHubId);
            return this;
        }
        @CustomType.Setter
        public Builder awrSnapshotCollections(List<GetAwrHubAwrSnapshotsAwrSnapshotCollection> awrSnapshotCollections) {
            this.awrSnapshotCollections = Objects.requireNonNull(awrSnapshotCollections);
            return this;
        }
        public Builder awrSnapshotCollections(GetAwrHubAwrSnapshotsAwrSnapshotCollection... awrSnapshotCollections) {
            return awrSnapshotCollections(List.of(awrSnapshotCollections));
        }
        @CustomType.Setter
        public Builder awrSourceDatabaseIdentifier(String awrSourceDatabaseIdentifier) {
            this.awrSourceDatabaseIdentifier = Objects.requireNonNull(awrSourceDatabaseIdentifier);
            return this;
        }
        @CustomType.Setter
        public Builder filters(@Nullable List<GetAwrHubAwrSnapshotsFilter> filters) {
            this.filters = filters;
            return this;
        }
        public Builder filters(GetAwrHubAwrSnapshotsFilter... filters) {
            return filters(List.of(filters));
        }
        @CustomType.Setter
        public Builder id(String id) {
            this.id = Objects.requireNonNull(id);
            return this;
        }
        @CustomType.Setter
        public Builder timeGreaterThanOrEqualTo(@Nullable String timeGreaterThanOrEqualTo) {
            this.timeGreaterThanOrEqualTo = timeGreaterThanOrEqualTo;
            return this;
        }
        @CustomType.Setter
        public Builder timeLessThanOrEqualTo(@Nullable String timeLessThanOrEqualTo) {
            this.timeLessThanOrEqualTo = timeLessThanOrEqualTo;
            return this;
        }
        public GetAwrHubAwrSnapshotsResult build() {
            final var o = new GetAwrHubAwrSnapshotsResult();
            o.awrHubId = awrHubId;
            o.awrSnapshotCollections = awrSnapshotCollections;
            o.awrSourceDatabaseIdentifier = awrSourceDatabaseIdentifier;
            o.filters = filters;
            o.id = id;
            o.timeGreaterThanOrEqualTo = timeGreaterThanOrEqualTo;
            o.timeLessThanOrEqualTo = timeLessThanOrEqualTo;
            return o;
        }
    }
}