// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Database.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.Database.outputs.GetManagedPreferredCredentialsPreferredCredentialCollectionItem;
import java.util.List;
import java.util.Objects;

@CustomType
public final class GetManagedPreferredCredentialsPreferredCredentialCollection {
    private List<GetManagedPreferredCredentialsPreferredCredentialCollectionItem> items;

    private GetManagedPreferredCredentialsPreferredCredentialCollection() {}
    public List<GetManagedPreferredCredentialsPreferredCredentialCollectionItem> items() {
        return this.items;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedPreferredCredentialsPreferredCredentialCollection defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private List<GetManagedPreferredCredentialsPreferredCredentialCollectionItem> items;
        public Builder() {}
        public Builder(GetManagedPreferredCredentialsPreferredCredentialCollection defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.items = defaults.items;
        }

        @CustomType.Setter
        public Builder items(List<GetManagedPreferredCredentialsPreferredCredentialCollectionItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetManagedPreferredCredentialsPreferredCredentialCollection", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetManagedPreferredCredentialsPreferredCredentialCollectionItem... items) {
            return items(List.of(items));
        }
        public GetManagedPreferredCredentialsPreferredCredentialCollection build() {
            final var _resultValue = new GetManagedPreferredCredentialsPreferredCredentialCollection();
            _resultValue.items = items;
            return _resultValue;
        }
    }
}
