// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Optimizer.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.oci.Optimizer.outputs.ProfileTargetTagsItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class ProfileTargetTags {
    /**
     * @return (Updatable) The list of tags specified in the current profile override.
     * 
     */
    private final List<ProfileTargetTagsItem> items;

    @CustomType.Constructor
    private ProfileTargetTags(@CustomType.Parameter("items") List<ProfileTargetTagsItem> items) {
        this.items = items;
    }

    /**
     * @return (Updatable) The list of tags specified in the current profile override.
     * 
     */
    public List<ProfileTargetTagsItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(ProfileTargetTags defaults) {
        return new Builder(defaults);
    }

    public static final class Builder {
        private List<ProfileTargetTagsItem> items;

        public Builder() {
    	      // Empty
        }

        public Builder(ProfileTargetTags defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        public Builder items(List<ProfileTargetTagsItem> items) {
            this.items = Objects.requireNonNull(items);
            return this;
        }
        public Builder items(ProfileTargetTagsItem... items) {
            return items(List.of(items));
        }        public ProfileTargetTags build() {
            return new ProfileTargetTags(items);
        }
    }
}
