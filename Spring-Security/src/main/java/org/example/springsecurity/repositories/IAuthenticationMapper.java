package org.example.springsecurity.repositories;

import org.apache.ibatis.annotations.Insert;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Update;
import org.example.springsecurity.configurations.security.UserInfo;
import org.example.springsecurity.requests.SignupReq;

@Mapper
public interface IAuthenticationMapper {
    @Select("SELECT * FROM users us WHERE us.username = #{username}")
    UserInfo findByUsername(@Param("username") String username);

    @Select("SELECT COUNT(*) FROM users WHERE username = #{username}")
    boolean isExistsUsername(@Param("username") String username);

    @Select("SELECT COUNT(*) FROM users WHERE email = #{email}")
    boolean isExistsEmail(@Param("email") String email);

    @Select("SELECT COUNT(*) FROM users WHERE mobile = #{mobile}")
    boolean isExistsMobile(@Param("mobile") String mobile);

    @Insert("INSERT INTO users (user_id, username, password, mobile, email) VALUES (#{uuid}, #{username}, #{password}, #{mobile}, #{email})")
    void signup(SignupReq request);

    @Select("SELECT password FROM users WHERE username = #{username}")
    String findPasswordByUserName(@Param("username") String username);

    @Update("UPDATE users SET password = #{newPassword} WHERE username = #{username}")
    void updatePassword(@Param("username") String username, @Param("newPassword") String newPassword);

    @Update("UPDATE users SET two_fa_secret = #{secret}, is_enable_two_fa = #{isEnable} WHERE username = #{username}")
    void updateTwoFaSecret(@Param("username") String username, @Param("secret") String secret, @Param("isEnable") boolean isEnable);
}
