// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class GetManagedDatabaseUserConsumerGroupPrivilegesConsumerGroupPrivilegeCollectionItem {
    /**
     * @return Indicates whether the privilege is granted with the GRANT option (YES) or not (NO).
     * 
     */
    private String grantOption;
    /**
     * @return Indicates whether the consumer group is designated as the default for this user or role (YES) or not (NO).
     * 
     */
    private String initialGroup;
    /**
     * @return A filter to return only resources that match the entire name.
     * 
     */
    private String name;

    private GetManagedDatabaseUserConsumerGroupPrivilegesConsumerGroupPrivilegeCollectionItem() {}
    /**
     * @return Indicates whether the privilege is granted with the GRANT option (YES) or not (NO).
     * 
     */
    public String grantOption() {
        return this.grantOption;
    }
    /**
     * @return Indicates whether the consumer group is designated as the default for this user or role (YES) or not (NO).
     * 
     */
    public String initialGroup() {
        return this.initialGroup;
    }
    /**
     * @return A filter to return only resources that match the entire name.
     * 
     */
    public String name() {
        return this.name;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseUserConsumerGroupPrivilegesConsumerGroupPrivilegeCollectionItem defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String grantOption;
        private String initialGroup;
        private String name;
        public Builder() {}
        public Builder(GetManagedDatabaseUserConsumerGroupPrivilegesConsumerGroupPrivilegeCollectionItem defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.grantOption = defaults.grantOption;
    	      this.initialGroup = defaults.initialGroup;
    	      this.name = defaults.name;
        }

        @CustomType.Setter
        public Builder grantOption(String grantOption) {
            this.grantOption = Objects.requireNonNull(grantOption);
            return this;
        }
        @CustomType.Setter
        public Builder initialGroup(String initialGroup) {
            this.initialGroup = Objects.requireNonNull(initialGroup);
            return this;
        }
        @CustomType.Setter
        public Builder name(String name) {
            this.name = Objects.requireNonNull(name);
            return this;
        }
        public GetManagedDatabaseUserConsumerGroupPrivilegesConsumerGroupPrivilegeCollectionItem build() {
            final var o = new GetManagedDatabaseUserConsumerGroupPrivilegesConsumerGroupPrivilegeCollectionItem();
            o.grantOption = grantOption;
            o.initialGroup = initialGroup;
            o.name = name;
            return o;
        }
    }
}