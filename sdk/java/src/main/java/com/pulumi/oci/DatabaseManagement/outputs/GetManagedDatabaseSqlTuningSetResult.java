// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.DatabaseManagement.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import com.pulumi.oci.DatabaseManagement.outputs.GetManagedDatabaseSqlTuningSetItem;
import java.lang.String;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import javax.annotation.Nullable;

@CustomType
public final class GetManagedDatabaseSqlTuningSetResult {
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    private String id;
    /**
     * @return The details in the SQL tuning set summary.
     * 
     */
    private List<GetManagedDatabaseSqlTuningSetItem> items;
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    private String managedDatabaseId;
    private @Nullable String nameContains;
    /**
     * @return The owner of the SQL tuning set.
     * 
     */
    private @Nullable String owner;

    private GetManagedDatabaseSqlTuningSetResult() {}
    /**
     * @return The provider-assigned unique ID for this managed resource.
     * 
     */
    public String id() {
        return this.id;
    }
    /**
     * @return The details in the SQL tuning set summary.
     * 
     */
    public List<GetManagedDatabaseSqlTuningSetItem> items() {
        return this.items;
    }
    /**
     * @return The [OCID](https://docs.cloud.oracle.com/iaas/Content/General/Concepts/identifiers.htm) of the Managed Database.
     * 
     */
    public String managedDatabaseId() {
        return this.managedDatabaseId;
    }
    public Optional<String> nameContains() {
        return Optional.ofNullable(this.nameContains);
    }
    /**
     * @return The owner of the SQL tuning set.
     * 
     */
    public Optional<String> owner() {
        return Optional.ofNullable(this.owner);
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(GetManagedDatabaseSqlTuningSetResult defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String id;
        private List<GetManagedDatabaseSqlTuningSetItem> items;
        private String managedDatabaseId;
        private @Nullable String nameContains;
        private @Nullable String owner;
        public Builder() {}
        public Builder(GetManagedDatabaseSqlTuningSetResult defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.id = defaults.id;
    	      this.items = defaults.items;
    	      this.managedDatabaseId = defaults.managedDatabaseId;
    	      this.nameContains = defaults.nameContains;
    	      this.owner = defaults.owner;
        }

        @CustomType.Setter
        public Builder id(String id) {
            if (id == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseSqlTuningSetResult", "id");
            }
            this.id = id;
            return this;
        }
        @CustomType.Setter
        public Builder items(List<GetManagedDatabaseSqlTuningSetItem> items) {
            if (items == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseSqlTuningSetResult", "items");
            }
            this.items = items;
            return this;
        }
        public Builder items(GetManagedDatabaseSqlTuningSetItem... items) {
            return items(List.of(items));
        }
        @CustomType.Setter
        public Builder managedDatabaseId(String managedDatabaseId) {
            if (managedDatabaseId == null) {
              throw new MissingRequiredPropertyException("GetManagedDatabaseSqlTuningSetResult", "managedDatabaseId");
            }
            this.managedDatabaseId = managedDatabaseId;
            return this;
        }
        @CustomType.Setter
        public Builder nameContains(@Nullable String nameContains) {

            this.nameContains = nameContains;
            return this;
        }
        @CustomType.Setter
        public Builder owner(@Nullable String owner) {

            this.owner = owner;
            return this;
        }
        public GetManagedDatabaseSqlTuningSetResult build() {
            final var _resultValue = new GetManagedDatabaseSqlTuningSetResult();
            _resultValue.id = id;
            _resultValue.items = items;
            _resultValue.managedDatabaseId = managedDatabaseId;
            _resultValue.nameContains = nameContains;
            _resultValue.owner = owner;
            return _resultValue;
        }
    }
}
