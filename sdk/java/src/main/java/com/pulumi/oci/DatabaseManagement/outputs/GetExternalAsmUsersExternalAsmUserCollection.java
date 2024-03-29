// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetExternalAsmUsersExternalAsmUserCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetExternalAsmUsersExternalAsmUserCollection {
    /**
     * @return An array of external ASM users.
     * 
     */
    private List<GetExternalAsmUsersExternalAsmUserCollectionItem> items;

    private GetExternalAsmUsersExternalAsmUserCollection() {}
    /**
     * @return An array of external ASM users.
     * 
     */
    public List<GetExternalAsmUsersExternalAsmUserCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetExternalAsmUsersExternalAsmUserCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetExternalAsmUsersExternalAsmUserCollectionItem> items;
        public Builder() {}
        public Builder(GetExternalAsmUsersExternalAsmUserCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetExternalAsmUsersExternalAsmUserCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetExternalAsmUsersExternalAsmUserCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetExternalAsmUsersExternalAsmUserCollectionItem... items) {
            return items(List.of(items));
        }
        public GetExternalAsmUsersExternalAsmUserCollection build() {
            final var _resultValue = new GetExternalAsmUsersExternalAsmUserCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
