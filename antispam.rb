#!/usr/bin/env ruby
#CAPTCHA-like picture generator for Aphorism registration
#Copyright (C) 2010 Anton Pirogov
#Licensed under the GPLv3 or later

module AntiSpam

  require 'RMagick'
  require 'base64'

  #give a random color (argument - a hash containing fixed parts of the color)
  def AntiSpam.randclrstr(colors={})
    colors = [colors[:r],colors[:g],colors[:b]]

    colors.map!{|color|
      if color==nil
        color = rand(256).to_s(16)
        color = "0"+color if color.length < 2
      end
      color = color.to_s(16) if color.class == Fixnum
      color
    }
    return colors.inject("#"){|str,color| str+=color}
  end

  #returns picture for data uri (base 64 encoded)
  def AntiSpam.generate_picture
    captcha_number = (rand(8999)+1000).to_s

    w=160
    h=120

    canvas = Magick::Image.new(w,h, Magick::HatchFill.new(randclrstr({:g=>255,:b=>255}),randclrstr({:r=>255})))
    gc = Magick::Draw.new

    elipsen = lambda {
      gc.stroke(randclrstr)
      gc.fill(randclrstr)
      gc.stroke_width(rand(5))
      gc.fill_opacity(rand(2)==1 || rand(0.1))
      gc.ellipse(rand(w),rand(h),rand(w),rand(h),rand(4)*90,270)
    }

    10.times{ elipsen.call }

    #prepare font
    offsetx, offsety = rand(3),rand(3)
    gc.stroke('black')
    gc.stroke_width(1)
    gc.font_family('Arial')
    gc.pointsize(20)
    gc.font_style(Magick::ItalicStyle)

    #draw the captcha number int] 1 of the 9 divisions
    x, y = offsetx*(w/4) + rand(w/4-20)+20,  offsety*(h/3) + rand(h/3-10)+10
        gc.text(x, y, captcha_number)

    10.times{ elipsen.call }

    gc.draw(canvas)

    canvas.format = "PNG"
    blob = canvas.to_blob         #get binary data of pic

    blob = Base64.encode64(blob)  #code base64 for data uri
    #blob.gsub!("\n","\\n")    #escape for json string
    #return data and number
    return [blob, captcha_number]
  end

end
