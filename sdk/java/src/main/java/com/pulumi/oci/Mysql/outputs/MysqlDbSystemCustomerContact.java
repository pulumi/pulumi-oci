// *** WARNING: this file was generated by pulumi-java-gen. ***
// *** Do not edit by hand unless you're certain you know what you are doing! ***

package com.pulumi.oci.Mysql.outputs;

import com.pulumi.core.annotations.CustomType;
import com.pulumi.exceptions.MissingRequiredPropertyException;
import java.lang.String;
import java.util.Objects;

@CustomType
public final class MysqlDbSystemCustomerContact {
    /**
     * @return (Updatable) The email address used by Oracle to send notifications regarding the DB System.
     * 
     */
    private String email;

    private MysqlDbSystemCustomerContact() {}
    /**
     * @return (Updatable) The email address used by Oracle to send notifications regarding the DB System.
     * 
     */
    public String email() {
        return this.email;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static Builder builder(MysqlDbSystemCustomerContact defaults) {
        return new Builder(defaults);
    }
    @CustomType.Builder
    public static final class Builder {
        private String email;
        public Builder() {}
        public Builder(MysqlDbSystemCustomerContact defaults) {
    	      Objects.requireNonNull(defaults);
    	      this.email = defaults.email;
        }

        @CustomType.Setter
        public Builder email(String email) {
            if (email == null) {
              throw new MissingRequiredPropertyException("MysqlDbSystemCustomerContact", "email");
            }
            this.email = email;
            return this;
        }
        public MysqlDbSystemCustomerContact build() {
            final var _resultValue = new MysqlDbSystemCustomerContact();
            _resultValue.email = email;
            return _resultValue;
        }
    }
}
