// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Jms.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Jms.outputs.GetInstallationSitesInstallationSiteCollectionItemItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetInstallationSitesInstallationSiteCollectionItem {
    /**
     * @return A list of Java installation sites.
     * 
     */
    private List<GetInstallationSitesInstallationSiteCollectionItemItem> items;

    private GetInstallationSitesInstallationSiteCollectionItem() {}
    /**
     * @return A list of Java installation sites.
     * 
     */
    public List<GetInstallationSitesInstallationSiteCollectionItemItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetInstallationSitesInstallationSiteCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetInstallationSitesInstallationSiteCollectionItemItem> items;
        public Builder() {}
        public Builder(GetInstallationSitesInstallationSiteCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetInstallationSitesInstallationSiteCollectionItemItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(GetInstallationSitesInstallationSiteCollectionItemItem... items) {
            return items(List.of(items));
        }
        public GetInstallationSitesInstallationSiteCollectionItem build() {
            final var o = new GetInstallationSitesInstallationSiteCollectionItem();
            o.items = items;
            return o;
        }
    }
}