// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Opsi.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Opsi.outputs.GetAwrHubAwrSnapshotsAwrSnapshotCollectionItemItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetAwrHubAwrSnapshotsAwrSnapshotCollectionItem {
    /**
     * @return A list of AWR snapshot summary data.
     * 
     */
    private List<GetAwrHubAwrSnapshotsAwrSnapshotCollectionItemItem> items;

    private GetAwrHubAwrSnapshotsAwrSnapshotCollectionItem() {}
    /**
     * @return A list of AWR snapshot summary data.
     * 
     */
    public List<GetAwrHubAwrSnapshotsAwrSnapshotCollectionItemItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetAwrHubAwrSnapshotsAwrSnapshotCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetAwrHubAwrSnapshotsAwrSnapshotCollectionItemItem> items;
        public Builder() {}
        public Builder(GetAwrHubAwrSnapshotsAwrSnapshotCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetAwrHubAwrSnapshotsAwrSnapshotCollectionItemItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetAwrHubAwrSnapshotsAwrSnapshotCollectionItemItem... items) {
            return items(List.of(items));
        }
        public GetAwrHubAwrSnapshotsAwrSnapshotCollectionItem build() {
            final var o = new GetAwrHubAwrSnapshotsAwrSnapshotCollectionItem();
            o.items = items;
            return o;
        }
    }
}